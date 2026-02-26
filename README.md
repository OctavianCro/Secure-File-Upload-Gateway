This project is a FastAPI application that securely handles file uploads while preventing common web application vulnerabilities.

The application allows a user to upload and download files, but only if they are the original owner. Authentication is simulated using an X User ID request header so the focus stays on access control logic.

This project implements multiple layers of security.

Only approved file types are allowed (png, jpeg, jpg, and pdf). File extensions are validated and the file signature is verified using magic byte inspection to prevent disguised malicious uploads.

Files are streamed in controlled chunks instead of being fully loaded into memory. A strict five megabyte size limit prevents memory exhaustion attacks.

Uploaded files are stored using generated UUID filenames instead of user supplied names. This prevents path traversal and filename manipulation.

Each file is associated with an owner. When a download request is made, the application verifies that the requesting user matches the file owner. Unauthorized access attempts return a 403 Forbidden response, preventing Insecure Direct Object Reference vulnerabilities under Broken Access Control.
