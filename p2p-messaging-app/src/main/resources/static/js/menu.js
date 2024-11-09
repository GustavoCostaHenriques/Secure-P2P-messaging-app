// Toggle the user dropdown
function toggleDropdown() {
    var userDropdown = document.getElementById('userDropdown');
    var addContactDropdown = document.getElementById('addContactDropdown');
    
    // If the Add Contact dropdown is open, close it
    if (addContactDropdown.style.display === 'block') {
        addContactDropdown.style.display = 'none';
    }

    // Toggle the user dropdown
    if (userDropdown.style.display === 'none' || userDropdown.style.display === '') {
        userDropdown.style.display = 'block';
    } else {
        userDropdown.style.display = 'none';
    }
}

// Toggle the add contact dropdown
function toggleAddContactDropdown() {
    var userDropdown = document.getElementById('userDropdown');
    var addContactDropdown = document.getElementById('addContactDropdown');
    document.getElementById('errorMessage').style.display = 'none';
    document.getElementById('errorMessage1').style.display = 'none';
    document.getElementById('contactName').value = null;

    // If the User dropdown is open, close it
    if (userDropdown.style.display === 'block') {
        userDropdown.style.display = 'none';
    }

    // Toggle the add contact dropdown
    if (addContactDropdown.style.display === 'none' || addContactDropdown.style.display === '') {
        addContactDropdown.style.display = 'block';
    } else {
        addContactDropdown.style.display = 'none';
    }
}

function toggleInterestsList() {
    var interestsList = document.getElementById("interestsList");
    var toggleButton = document.getElementById("toggleInterestsButton");

    if (interestsList.style.display === "none" || interestsList.style.display === "") {
        interestsList.style.display = "block";
        toggleButton.textContent = "Hide Interests";
    } else {
        interestsList.style.display = "none";
        toggleButton.textContent = "Show Interests";
    }
}

function saveChanges() {
    var urlParams = new URLSearchParams(window.location.search);
    var peerId = urlParams.get('peerId');

    var selectedTopics = [];
    document.querySelectorAll('#dropdown_interests-menu input[type="checkbox"]:checked').forEach(checkbox => {
        selectedTopics.push(checkbox.value);
    });

    fetch('/saveChanges?peerId=' + peerId, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ topics: selectedTopics })
    })
    .then(response => {
        if (response.ok) {
            const noInterestsMessage = document.getElementById('noInterestsMessage');
            const interestsContainer = document.getElementById('interestsContainer');
            const interestsList = document.getElementById('interestsList');
            interestsList.innerHTML = ""; 

            if (selectedTopics.length > 0) {
                if (noInterestsMessage) noInterestsMessage.style.display = "none";
                interestsContainer.style.display = "block";
                selectedTopics.forEach(topic => {
                    const li = document.createElement('li');
                    li.textContent = topic;
                    interestsList.appendChild(li);
                });
            } else {
                if (noInterestsMessage) noInterestsMessage.style.display = "none";
                interestsContainer.style.display = "none";
            }

            toggleDropdown_interests();
            toggleDropdown();
        } else {
            console.error("Failed to update interests.");
        }
    })
    .catch(error => console.error("Error:", error));
}

function logout() {
    // Get the peerId from the current URL
    var urlParams = new URLSearchParams(window.location.search);
    var peerId = urlParams.get('peerId');

    // Send a POST request to the logout endpoint with the peerId
    fetch('/logout?peerId=' + peerId, {
        method: 'POST',
    })
    .then(response => response.text())
    .then(result => {
        if (result === 'success') {
            // Redirect to the welcome page after logout
            window.location.href = '/';
        } else {
            console.error('Error during logout.');
        }
    })
    .catch(error => {
        console.error('Error during logout:', error);
    });
}

function startChat() {
    var contactName = document.getElementById('contactName').value;
    var urlParams = new URLSearchParams(window.location.search);
    var peerId = urlParams.get('peerId');

    fetch('/startChat?peerId=' + peerId + '&contactName=' + contactName , {
        method: 'POST',
    })
    .then(response => response.text())
    .then(result => {
        if (result === 'exists') {
            addConversation(contactName);
            addContactDropdown.style.display = 'none';
        } else if (result === 'not found') {
            document.getElementById('errorMessage1').style.display = 'none';
            document.getElementById('errorMessage').style.display = 'block';
        } else if (result === 'your own name') {
            document.getElementById('errorMessage').style.display = 'none';
            document.getElementById('errorMessage1').style.display = 'block';
        }
        else {
            console.error('An error occurred.');
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function addConversation(contactName) {
    var conversationList = document.querySelector('.conversation-list');
    var exists = Array.from(conversationList.children).find(item => item.textContent.trim() === contactName);
    if (!exists) {
        var newConversation = document.createElement('li');
        newConversation.classList.add('conversation-container');
        newConversation.setAttribute('data-contact', contactName);
        newConversation.innerHTML = '<img src="/images/user.png"> ' + contactName;
        
        newConversation.onclick = function () {
            selectConversation(newConversation);
        };

        conversationList.appendChild(newConversation);

        selectConversation(newConversation);
    }
    selectConversation(exists);
    document.getElementById('errorMessage').style.display = 'none'; 
    document.getElementById('addContactDropdown').style.display = 'none'; 
}

function selectConversation(element) {
    document.querySelectorAll('.conversation-container').forEach(conversation => {
        conversation.classList.remove('active');
    });

    element.classList.add('active');
    const contact = element.getAttribute("data-contact");

    // Get peerId and contactName
    var urlParams = new URLSearchParams(window.location.search);
    var peerId = urlParams.get('peerId');;
    var contactName = element.getAttribute("data-contact");

    toggleChatPanel();

    // Load chat messages
    loadChatMessages(peerId, contactName);

    startPollingForMessages(peerId, contactName);
}

function toggleChatPanel() {
    const chatPanel = document.getElementById('chatPanel');
    const chatActivePanel = document.getElementById('chatActivePanel');
    const activeConversation = document.querySelector('.conversation-container.active');

    // Show chatActivePanel if a conversation is active; otherwise, show chatPanel
    if (activeConversation) {
        chatPanel.style.display = 'none';
        chatActivePanel.style.display = 'flex';
    } else {
        chatPanel.style.display = 'flex';
        chatActivePanel.style.display = 'none';
    }
}


function loadChatMessages(peerId, contactName) {
    const chatMessagesContainer = document.querySelector('.chat-messages');
    chatMessagesContainer.innerHTML = ''; // Clear existing messages

    fetch(`/loadChat?peerId=${peerId}&contactName=${contactName}`)
        .then(response => response.json())
        .then(messages => {
            messages.forEach(message => {
                const messageElement = document.createElement('div');
                messageElement.classList.add('message');

                const [timestampAndSender, messageContent] = message.split('] ');
                const [fullTimestamp, sender] = timestampAndSender.split('-[');
                const senderId = sender.replace('[', '').replace(']', '');

                const time = fullTimestamp.split('T')[1].substring(0, 5); 

                if (senderId === peerId) {
                    // Mensagem enviada pelo próprio utilizador (sem o nome)
                    messageElement.classList.add('sent');
                    messageElement.innerHTML = `
                        <p>${messageContent}</p>
                        <span class="timestamp">${time}</span>
                    `;
                } else {
                    // Mensagem recebida (com o nome do remetente)
                    messageElement.classList.add('received');
                    messageElement.innerHTML = `
                        <span class="sender">${senderId}</span>
                        <p>${messageContent}</p>
                        <span class="timestamp">${time}</span>
                    `;
                }

                chatMessagesContainer.appendChild(messageElement);
            });
            chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
        })
        .catch(error => {
            console.error('Error loading messages:', error);
        });
}

function sendMessage() {
    document.getElementById('errorMessage2').style.display = 'none';
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();

    if (message) {
        const activeConversation = document.querySelector('.conversation-container.active');
        const contactName = activeConversation.getAttribute("data-contact");
        
        var urlParams = new URLSearchParams(window.location.search);
        var peerId = urlParams.get('peerId');
        // Clear the input field after sending
        fetch('/sendMessage?peerId=' + peerId + '&contactName=' + contactName + '&message=' + message, {
            method: 'POST',
        })
        .then(response => response.text())
        .then(result => {
            if (result === 'success') {
                loadChatMessages(peerId,contactName);
            } else if (result === 'not found') {
                document.getElementById('errorMessage2').style.display = 'block';
            }
            else {
                console.error('An error occurred.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });

        messageInput.value = '';
    }
}

function startPollingForMessages(peerId, contactName) {
    setInterval(() => {
        loadChatMessages(peerId, contactName);
    }, 5000); 
}

function toggleDropdown_interests() {
    var dropdownMenu = document.getElementById("dropdown_interests-menu");
    if (dropdownMenu.style.display === "none" || dropdownMenu.style.display === "") {
        dropdownMenu.style.display = "block";
    } else {
        dropdownMenu.style.display = "none";
    }
}

window.addEventListener("click", function(event) {
    var dropdownButton = document.querySelector(".dropdown_interests-button");
    var dropdownMenu = document.getElementById("dropdown_interests-menu");

    if (!dropdownButton.contains(event.target) && !dropdownMenu.contains(event.target)) {
        dropdownMenu.style.display = "none";
    }
});

document.addEventListener('DOMContentLoaded', function () {
    var userInterests = document.getElementById("interestsList");
    var interestsContainer = document.getElementById("interestsContainer");
    var noInterestsMessage = document.getElementById("noInterestsMessage");

    // Verifica se há interesses para mostrar
    if (userInterests && userInterests.childElementCount > 0) {
        interestsContainer.style.display = "block"; // Mostra o container dos interesses
        if (noInterestsMessage) noInterestsMessage.style.display = "none";  // Oculta a mensagem de "No interests selected"
    } else {
        interestsContainer.style.display = "none";  // Oculta o container dos interesses
        if (noInterestsMessage) noInterestsMessage.style.display = "block"; // Mostra a mensagem de "No interests selected"
    }
});

// Initial check on page load
document.addEventListener('DOMContentLoaded', toggleChatPanel);
