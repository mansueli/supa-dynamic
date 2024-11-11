CREATE EXTENSION IF NOT EXISTS http WITH SCHEMA extensions;
CREATE SCHEMA IF NOT EXISTS edge;
CREATE OR REPLACE FUNCTION edge.edge_wrapper(
    url TEXT,
    method TEXT DEFAULT 'POST',
    headers JSONB DEFAULT '{"Content-Type": "application/json"}'::jsonb,
    params JSONB DEFAULT '{}'::jsonb,
    payload JSONB DEFAULT '{}'::jsonb, -- Payload as JSONB
    timeout_ms INTEGER DEFAULT 5000,
    max_retries INTEGER DEFAULT 0,
    allowed_regions TEXT[] DEFAULT NULL
) RETURNS jsonb 
   SET search_path = ''
   LANGUAGE plpgsql
AS $$
DECLARE
    retry_count INTEGER := 0;
    retry_delays DOUBLE PRECISION[] := ARRAY[0, 0.250, 0.500, 1.000, 2.500, 5.000];
    succeeded BOOLEAN := FALSE;
    current_region_index INTEGER := 1; -- Start index at 1 for PostgreSQL array
    combined_headers JSONB;
    response_json JSONB;
BEGIN
    -- Validate headers, params, and payload are JSON objects
    IF headers IS NULL OR NOT jsonb_typeof(headers) = 'object' THEN
        RAISE EXCEPTION 'Invalid headers parameter: %', headers;
    END IF;

    IF params IS NULL OR NOT jsonb_typeof(params) = 'object' THEN
        RAISE EXCEPTION 'Invalid params parameter: %', params;
    END IF;

    IF payload IS NULL OR NOT jsonb_typeof(payload) = 'object' THEN
        RAISE EXCEPTION 'Invalid payload parameter: %', payload;
    END IF;

    -- Validate allowed_regions if provided
    IF allowed_regions IS NOT NULL AND cardinality(allowed_regions) = 0 THEN
        RAISE EXCEPTION 'allowed_regions parameter cannot be an empty array';
    END IF;

    -- Check if retry_delays has enough elements
    IF cardinality(retry_delays) < max_retries + 1 THEN
        RAISE EXCEPTION 'retry_delays array must have at least % elements', max_retries + 1;
    END IF;

    -- Retry loop
    WHILE NOT succeeded AND retry_count <= max_retries LOOP
        combined_headers := headers;

        -- Set x-region header if allowed_regions is provided
        IF allowed_regions IS NOT NULL AND cardinality(allowed_regions) > 0 THEN
            combined_headers := combined_headers || jsonb_build_object('x-region', allowed_regions[current_region_index]);
        END IF;

        -- Sleep if not the first attempt
        IF retry_count > 0 THEN
            PERFORM pg_sleep(retry_delays[retry_count]);
        END IF;

        retry_count := retry_count + 1;

        -- Increment region index, wrapping around if necessary
        IF allowed_regions IS NOT NULL AND cardinality(allowed_regions) > 0 THEN
            current_region_index := current_region_index + 1;
            IF current_region_index > cardinality(allowed_regions) THEN
                current_region_index := 1;
            END IF;
        END IF;

        BEGIN
            RAISE WARNING 'headers:%s', combined_headers;

            -- Call the simplified HTTP request function
            response_json := edge.http_request(url, method, combined_headers, params, payload, timeout_ms);

            -- Check the status code
            IF (response_json->>'status_code')::INTEGER < 500 THEN
                succeeded := TRUE;
            END IF;
        EXCEPTION
            WHEN OTHERS THEN
                IF retry_count > max_retries THEN
                    RAISE EXCEPTION 'HTTP request failed after % retries. SQL Error: { %, % }',
                        max_retries, SQLERRM, SQLSTATE;
                END IF;
        END;
    END LOOP;
    RETURN response_json;
END;
$$;

CREATE OR REPLACE FUNCTION edge.http_request(
    url TEXT,
    method TEXT DEFAULT 'POST',
    headers JSONB DEFAULT '{"Content-Type": "application/json"}'::jsonb,
    params JSONB DEFAULT '{}'::jsonb,
    payload JSONB DEFAULT '{}'::jsonb,
    timeout_ms INTEGER DEFAULT 5000
) RETURNS jsonb
   LANGUAGE plpgsql
   SET search_path = ''
AS $$
DECLARE
    http_response extensions.http_response;
    status_code integer := 0;
    response_json jsonb;
    response_text text;
    header_array extensions.http_header[];
    request extensions.http_request;
BEGIN
    -- Set the timeout option
    IF timeout_ms > 0 THEN
        PERFORM http_set_curlopt('CURLOPT_TIMEOUT_MS', timeout_ms::text);
    END IF;

    -- Convert headers JSONB to http_header array
    SELECT array_agg(extensions.http_header(key, value::text))
    FROM jsonb_each_text(headers)
    INTO header_array;

    -- Construct the http_request composite type
    request := ROW(method, url, header_array, 'application/json', payload::text)::extensions.http_request;

    -- Make the HTTP request
    http_response := http(request);
    status_code := http_response.status;

    -- Attempt to extract JSONB response content
    BEGIN
        response_json := http_response.content::jsonb;
    EXCEPTION
        WHEN others THEN
            response_text := http_response.content;
            response_json := jsonb_build_object('status_code', status_code, 'response', response_text);
    END;

    RETURN jsonb_build_object('status_code', status_code, 'response', response_json);
END;
$$;


CREATE OR REPLACE FUNCTION edge.get_secret(secret_name text) RETURNS text
    LANGUAGE "plpgsql"
    SET search_path = ''
    AS $$
DECLARE
    decrypted text;
BEGIN
    IF current_setting('request.jwt.claims', true)::jsonb->>'role' = 'service_role' OR current_user = 'postgres' THEN
        SELECT decrypted_secret
        INTO decrypted
        FROM vault.decrypted_secrets
        WHERE name = secret_name;
        RETURN decrypted;
    ELSE
        RAISE EXCEPTION 'Access denied: only service_role or postgres user can execute this function.';
    END IF;
END;
$$;
-- If you want to access the secrets with the service_role in the API:
GRANT pgsodium_keyiduser TO service_role;
