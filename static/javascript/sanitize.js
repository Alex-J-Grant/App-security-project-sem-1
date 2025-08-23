
export function sanitizeInput(input) {
    return DOMPurify.sanitize(input, {ALLOWED_TAGS: [], ALLOWED_ATTR: []});
}