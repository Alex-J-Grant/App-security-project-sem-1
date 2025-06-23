export function sanitizeInput(input) {

    let sanitizedInput = input

    //replace with the non html kind
    sanitizedInput = sanitizedInput.replace(/&/g, "&amp;")
                                   .replace(/</g, "&lt;")
                                   .replace(/>/g, "&gt;")
                                   .replace(/"/g, "&quot;")
                                   .replace(/'/g, "&#x27;");

    // Step 3: Return sanitized input
    return sanitizedInput;
}