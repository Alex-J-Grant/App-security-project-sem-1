import { sanitizeInput } from '/static/javascript/sanitize.js';
        document.getElementById('chatbot-button').addEventListener('click', function() {
            const chatbox = document.getElementById('chatboxer');
            chatbox.style.display = 'block';  // Open chatbox
        });
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        document.getElementById('x').addEventListener('click', function() {
            const chatbox = document.getElementById('chatboxer');
            chatbox.style.display = 'none';  // Close chatbox
        });
        document.getElementById('chatbot-enter').addEventListener('click', function() {
            let user_input = sanitizeInput(document.getElementById('user_input').value); // Sanitize user input

            if (user_input) {
                let chatbox = document.getElementById('chatbox');
                chatbox.innerHTML += '<div class="user-message">' + user_input + '</div>'; // add user input
                let thinkingMessage = '<div class="bot-response thinking" name="think">Thinking...</div>';
                chatbox.innerHTML += thinkingMessage;
                chatbox.scrollTop = chatbox.scrollHeight;

                // Send the input to the server via AJAX
                fetch('/chatbot', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded','X-CSRFToken': csrfToken},
                    body: 'user_input=' + encodeURIComponent(user_input)

                })
                .then(response => response.json())
                .then(data => {
                    console.log(data.response);
                    let botResponseHtml = DOMPurify.sanitize(marked.parse(data.response), {
        USE_PROFILES: { html: true }});
                    console.log(botResponseHtml);
                    let thinkingElement = document.querySelector('.thinking');
                        if (thinkingElement) {
                            thinkingElement.outerHTML = '<div class="bot-response">' + botResponseHtml + '</div>';
                        }
                    chatbox.scrollTop = chatbox.scrollHeight;
                });

                // Clear input field
                document.getElementById('user_input').value = '';
            }
        });