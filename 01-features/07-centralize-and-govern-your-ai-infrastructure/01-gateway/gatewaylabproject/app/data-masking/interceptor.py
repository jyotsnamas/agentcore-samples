"""
PII Masking Interceptor for Gateway MCP RESPONSES using Bedrock Guardrails

This Lambda function intercepts Gateway MCP tools/call RESPONSES and masks
sensitive PII data using Amazon Bedrock Guardrails API for ALL tool responses.
It is configured as a RESPONSE interceptor that transforms any tool response.
"""

import json
import os
import boto3
from typing import Any, Dict

# Initialize Bedrock Runtime client
bedrock_runtime = boto3.client("bedrock-runtime")

# Get Guardrail configuration from environment variables
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

# Payload logging is OFF by default: this interceptor handles the very PII it is
# masking, so echoing request/response bodies to CloudWatch would defeat the
# control (log readers would see the unmasked values). Set
# DEBUG_LOG_PAYLOADS=true only in a throwaway account when debugging.
DEBUG_LOG_PAYLOADS = os.environ.get("DEBUG_LOG_PAYLOADS", "false").lower() == "true"


def _log_payload(label: str, payload: Any) -> None:
    """Log a payload only when explicitly opted in; otherwise log its size only."""
    if DEBUG_LOG_PAYLOADS:
        print(f"[DEBUG] {label}: {json.dumps(payload, default=str)}")
    else:
        size = len(json.dumps(payload, default=str)) if payload is not None else 0
        print(f"[DEBUG] {label}: <redacted {type(payload).__name__}, {size} bytes>")


def _log_text(label: str, text: str) -> None:
    """Log free text only when explicitly opted in; otherwise log its length only."""
    if DEBUG_LOG_PAYLOADS:
        print(f"[DEBUG] {label}: {text[:300]}")
    else:
        print(f"[DEBUG] {label}: <redacted, {len(text)} chars>")


def mask_pii_with_guardrails(text: str) -> str:
    """
    Use Bedrock Guardrails to mask PII in text.

    Args:
        text: Text content that may contain PII

    Returns:
        Text with PII masked/anonymized by Guardrails
    """
    _log_text("mask_pii_with_guardrails - INPUT text", text)

    if not GUARDRAIL_ID:
        print("[DEBUG] WARNING: GUARDRAIL_ID not configured, skipping PII masking")
        print(
            "[DEBUG] mask_pii_with_guardrails - RETURNING original text (no guardrail)"
        )
        return text

    try:
        print(
            f"[DEBUG] Calling Bedrock Guardrails API with ID: {GUARDRAIL_ID}, Version: {GUARDRAIL_VERSION}"
        )

        # Apply guardrail to the text
        response = bedrock_runtime.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            source="OUTPUT",  # We're filtering output from tools
            outputScope="FULL",
            content=[{"text": {"text": text}}],
        )

        _log_payload("Guardrails API response received", response)

        # Extract the masked text from the response
        outputs = response.get("outputs", [])
        if outputs and len(outputs) > 0:
            masked_text = outputs[0].get("text", text)
            _log_text("Extracted masked_text", masked_text)

            # Log PII detection details
            usage = response.get("usage", {})
            assessments = response.get("assessments", [])

            if usage.get("contentPolicyUnits", 0) > 0:
                print("[DEBUG] PII detected and anonymized by Guardrails")

                # Log what types of PII were detected
                if assessments:
                    for assessment in assessments:
                        sensitive_info = assessment.get(
                            "sensitiveInformationPolicy", {}
                        )
                        pii_entities = sensitive_info.get("piiEntities", [])
                        if pii_entities:
                            detected_types = [
                                entity.get("type") for entity in pii_entities
                            ]
                            print(
                                f"[DEBUG]   Detected PII types: {', '.join(detected_types)}"
                            )

            print("[DEBUG] mask_pii_with_guardrails - RETURNING masked_text")
            return masked_text

        print("[DEBUG] No outputs from Guardrails, RETURNING original text")
        return text

    except Exception as e:
        error_message = str(e)
        print(f"[DEBUG] ERROR applying Guardrails: {error_message}")
        print(f"[DEBUG]   Guardrail ID: {GUARDRAIL_ID}")
        print(f"[DEBUG]   Guardrail Version: {GUARDRAIL_VERSION}")

        # Check if it's a validation error about guardrail not existing
        if "does not exist" in error_message or "ValidationException" in error_message:
            print("[DEBUG]   ⚠ The Guardrail ID or version is invalid or doesn't exist")
            print(
                "[DEBUG]   ⚠ Make sure Step 1.3 was run successfully to create the Guardrail"
            )
            print(
                "[DEBUG]   ⚠ Verify the Lambda environment variables are set correctly"
            )

        # On error, return original text (fail open to avoid blocking)
        print(
            "[DEBUG] mask_pii_with_guardrails - RETURNING original text (error occurred)"
        )
        return text


def mask_tool_response(response_body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask PII in tool response by extracting text from body->result->content->text,
    parsing the JSON, anonymizing it with Bedrock Guardrails, and reconstructing properly.

    Args:
        response_body: MCP JSON-RPC response body

    Returns:
        Response body with masked PII in the text field
    """
    _log_payload("mask_tool_response - INPUT response_body", response_body)

    # Create a deep copy to avoid modifying the original
    masked_response = json.loads(json.dumps(response_body))
    print("[DEBUG] Created deep copy of response_body")

    # Navigate to body->result->content
    if "result" not in masked_response:
        print("[DEBUG] No 'result' field in response_body")
        return masked_response

    if "content" not in masked_response["result"]:
        print("[DEBUG] No 'content' field in result")
        return masked_response

    content_list = masked_response["result"]["content"]
    if not isinstance(content_list, list) or len(content_list) == 0:
        print("[DEBUG] 'content' is not a list or is empty")
        return masked_response

    print(f"[DEBUG] Processing {len(content_list)} content items")

    # Process each content item
    for i, content_item in enumerate(content_list):
        if content_item.get("type") != "text":
            print(f"[DEBUG] Content item {i} is not type 'text', skipping")
            continue

        text_value = content_item.get("text", "")
        if not text_value:
            print(f"[DEBUG] Content item {i} has empty text, skipping")
            continue

        _log_text(f"Content item {i} text", text_value)

        try:
            # Try to parse the text as JSON
            parsed_json = json.loads(text_value)
            print("[DEBUG] Successfully parsed text as JSON")
            _log_payload("Parsed JSON structure", parsed_json)

            # Convert the parsed JSON to a pretty string for Guardrails processing
            json_string = json.dumps(parsed_json, indent=2)
            _log_text("Converted to JSON string for Guardrails", json_string)

            # Apply Bedrock Guardrails to anonymize the JSON content
            print("[DEBUG] Applying Bedrock Guardrails to anonymize JSON content...")
            anonymized_json_string = mask_pii_with_guardrails(json_string)
            print(
                f"[DEBUG] Anonymized JSON string (first 300 chars): {anonymized_json_string[:300]}"
            )

            # Parse the anonymized string back to JSON object
            try:
                anonymized_json = json.loads(anonymized_json_string)
                print("[DEBUG] Successfully parsed anonymized string back to JSON")
                _log_payload("Anonymized JSON object", anonymized_json)

                # Replace with the JSON object directly (not as a string)
                masked_response["result"]["content"][i]["text"] = anonymized_json
                print(
                    f"[DEBUG] Replaced text in content item {i} with JSON object (not string)"
                )

            except json.JSONDecodeError as e:
                print(f"[DEBUG] Failed to parse anonymized string back to JSON: {e}")
                print("[DEBUG] Using anonymized string as-is")
                masked_response["result"]["content"][i]["text"] = anonymized_json_string

        except json.JSONDecodeError:
            # Not JSON, treat as plain text
            print("[DEBUG] Text is not JSON, treating as plain text")

            # Apply Bedrock Guardrails to anonymize the text
            print("[DEBUG] Applying Bedrock Guardrails to anonymize plain text...")
            anonymized_text = mask_pii_with_guardrails(text_value)
            _log_text("Anonymized text", anonymized_text)

            # Replace the text back in the response
            masked_response["result"]["content"][i]["text"] = anonymized_text
            print(f"[DEBUG] Replaced text in content item {i}")

    print("[DEBUG] mask_tool_response - RETURNING masked_response")
    return masked_response


def lambda_handler(event, context):
    """
    Main Lambda handler for Gateway RESPONSE interceptor.

    This handler applies PII masking to ALL tool responses using Bedrock Guardrails.

    Expected event structure (from Gateway RESPONSE for tools/call):
    {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayResponse": {
                "headers": {...},
                "body": {
                    "jsonrpc": "2.0",
                    "id": "invoke-tool-request",
                    "result": {
                        "isError": false,
                        "content": [
                            {
                                "type": "text",
                                "text": "{...tool data with potential PII...}"
                            }
                        ]
                    }
                },
                "statusCode": 200
            },
            "gatewayRequest": {...}
        }
    }

    Returns transformed response with masked PII for any tool.
    """
    print("[DEBUG] ========== LAMBDA HANDLER START ==========")
    _log_payload("PII Masking Interceptor - Received event", event)

    try:
        # Extract MCP data
        mcp_data = event.get("mcp", {})
        _log_payload("Extracted mcp_data", mcp_data)

        gateway_response = mcp_data.get("gatewayResponse", {})
        _log_payload("Extracted gateway_response", gateway_response)

        gateway_request = mcp_data.get("gatewayRequest", {})
        _log_payload("Extracted gateway_request", gateway_request)

        # Get response data
        response_headers = gateway_response.get("headers", {})
        # Log header names only — header values can carry bearer tokens.
        print(f"[DEBUG] response_headers (names only): {sorted(response_headers)}")

        response_body = gateway_response.get("body", {})
        _log_payload("response_body", response_body)

        status_code = gateway_response.get("statusCode", 200)
        print(f"[DEBUG] status_code: {status_code}")

        # Get request data to check which tool was called
        request_body = gateway_request.get("body", {})
        _log_payload("request_body", request_body)

        method = request_body.get("method", "")
        print(f"[DEBUG] Method: {method}")

        # Only process tools/call responses
        if method == "tools/call":
            params = request_body.get("params", {})
            tool_name = params.get("name", "")

            print(f"[DEBUG] Tool called: {tool_name}")
            print("[DEBUG] Applying PII masking to tool response...")

            # Mask PII in the response for any tool
            masked_body = mask_tool_response(response_body)

            _log_payload("Masked response body", masked_body)

            # Build return object
            return_obj = {
                "interceptorOutputVersion": "1.0",
                "mcp": {
                    "transformedGatewayResponse": {
                        "headers": response_headers,
                        "body": masked_body,
                        "statusCode": status_code,
                    }
                },
            }

            _log_payload("lambda_handler - RETURNING (tools/call)", return_obj)
            print("[DEBUG] ========== LAMBDA HANDLER END (tools/call) ==========")
            return return_obj

        # Pass through unchanged for non-customer-data responses
        print("[DEBUG] Method is not 'tools/call', passing through unchanged")

        passthrough_obj = {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayResponse": {
                    "headers": response_headers,
                    "body": response_body,
                    "statusCode": status_code,
                }
            },
        }

        _log_payload("lambda_handler - RETURNING (passthrough)", passthrough_obj)
        print("[DEBUG] ========== LAMBDA HANDLER END (passthrough) ==========")
        return passthrough_obj

    except Exception as e:
        print(f"[DEBUG] ERROR in lambda_handler: {e}")

        import traceback

        print(f"[DEBUG] Traceback: {traceback.format_exc()}")

        # On error, pass through unchanged (safer than blocking)
        error_obj = {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayResponse": {
                    "headers": gateway_response.get("headers", {}),
                    "body": gateway_response.get("body", {}),
                    "statusCode": gateway_response.get("statusCode", 500),
                }
            },
        }

        _log_payload("lambda_handler - RETURNING (error)", error_obj)
        print("[DEBUG] ========== LAMBDA HANDLER END (error) ==========")
        return error_obj
