# Implement Conversational Memory and Agentic Routing

This plan introduces DynamoDB-backed memory and Bedrock Tool Use (Function Calling) to TrailWhisperer. This allows the LLM to remember conversation history and decide whether to query Athena or respond directly to the user.

## Proposed Changes

### Infrastructure

#### [MODIFY] investigator-stack.yaml
- Add a new `AWS::DynamoDB::Table` resource named `ChatSessionsTable`.
  - `BillingMode: PAY_PER_REQUEST`
  - Partition Key: `session_id` (String)
  - TimeToLiveSpecification: `ttl` (Enabled: true)
- Update `OrchestratorRole` to include `dynamodb:PutItem`, `dynamodb:GetItem`, `dynamodb:UpdateItem` for the new table.
- Pass the table name to `OrchestratorFunction` as `DYNAMODB_SESSION_TABLE`.

### Backend

#### [MODIFY] backend/main.py
- **DynamoDB Integration**: Add helper functions to fetch and append conversation history to DynamoDB. Items should include a TTL of 24 hours.
- **Prompt Engineering**: Update `SQL_SYSTEM` to instruct the model to act as a security analyst. The model should answer questions directly using conversation history OR use the `query_athena` tool if new database queries are needed.
- **Bedrock API**: Update the `_invoke` function to accept a `messages` array and a `toolConfig` (defining the `query_athena` tool with a `sql` parameter).
- **`/api/generate-sql`**: 
  - Read `session_id` from the request.
  - Fetch history and append the new user question.
  - Invoke Bedrock.
  - If Bedrock invokes the `query_athena` tool, extract the `sql` and return it to the frontend for approval (do not execute it yet).
  - If Bedrock returns plain text (no tool call), save the assistant message to DynamoDB and return `{ "chat_response": "..." }` to the frontend.
- **`/api/results`**: 
  - After getting results from Athena and generating the summary, append the system/assistant result back to the DynamoDB `session_id` history so the model "remembers" the data for future questions.

### Frontend

#### [MODIFY] frontend/app.js
- Generate a unique `session_id` (e.g., UUID) when the app loads. Optionally persist it in `localStorage`.
- Update API calls (`/api/generate-sql`, etc.) to include `session_id` in the request body.
- Update the response handler for `/api/generate-sql`:
  - If the response contains `sql`, open the approval modal as before.
  - If the response contains `chat_response`, append the text to the chat window immediately without showing the modal.
