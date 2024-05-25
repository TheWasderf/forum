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
