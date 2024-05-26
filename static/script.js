// scripts.js
document.addEventListener('DOMContentLoaded', function() {
    const likeButton = document.getElementById('likeButton');
    const dislikeButton = document.getElementById('dislikeButton');

    likeButton.addEventListener('click', function(event) {
        event.preventDefault();
        sendLikeDislikeRequest('like');
    });

    dislikeButton.addEventListener('click', function(event) {
        event.preventDefault();
        sendLikeDislikeRequest('dislike');
    });
});

function sendLikeDislikeRequest(type) {
    const threadId = document.querySelector('input[name="thread_id"]').value;
    fetch('/like-dislike', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `thread_id=${threadId}&like_type=${type}`
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
        // Update UI based on response
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}


//chat starts
document.addEventListener('DOMContentLoaded', function() {
    const messageForm = document.getElementById('message-form');
    const recipientInput = document.getElementById('recipient');
    const contentInput = document.getElementById('message-content');

    let currentUsername = ''; // Initialize as empty

    // Fetch the current username from the server
    fetch('/api/get-current-user')
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to fetch user');
        }
        return response.json();
    })
    .then(data => {
        currentUsername = data.username; // Store the fetched username
        loadMessages(); // Load messages after getting the username
    })
    .catch(error => {
        console.error('Failed to fetch current user:', error);
    });

    function sendMessage() {
        const recipient = recipientInput.value;
        const content = contentInput.value;

        fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: currentUsername,
                recipient: recipient,
                content: content
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Message sent!');
            contentInput.value = ''; // Clear the message input
            loadMessages(); // Refresh the message list
        })
        .catch(error => console.error('Error:', error));
    }

    function loadMessages() {
        fetch('/api/messages')
        .then(response => response.json())
        .then(messages => {
            const messageList = document.getElementById('message-list');
            messageList.innerHTML = ''; // Clear current messages
            messages.forEach(message => {
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message';
                messageDiv.innerHTML = `<strong>From:</strong> ${message.username} <br> ${message.content}`;
                messageList.appendChild(messageDiv);
            });
        })
        .catch(error => console.error('Error loading messages:', error));
    }

    messageForm.addEventListener('submit', function(event) {
        event.preventDefault();
        sendMessage();
    });
});
//chat ends