// Toggle the user dropdown
function toggleDropdown() {
    var userDropdown = document.getElementById('userDropdown');
    var searchContainer = document.getElementById('search-container');
    var addContactDropdown = document.getElementById('addContactDropdown');
    
    // If the Add Contact dropdown is open, close it
    if (addContactDropdown.style.display === 'block') {
        addContactDropdown.style.display = 'none';
    }

    if (searchContainer.style.display === 'block') {
        searchContainer.style.display = 'none';
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
    var searchContainer = document.getElementById('search-container');
    var addContactDropdown = document.getElementById('addContactDropdown');
    document.getElementById('errorMessage').style.display = 'none';
    document.getElementById('errorMessage1').style.display = 'none';
    document.getElementById('contactName').value = null;

    // If the User dropdown is open, close it
    if (userDropdown.style.display === 'block') {
        userDropdown.style.display = 'none';
    }

    if (searchContainer.style.display === 'block') {
        searchContainer.style.display = 'none';
    }

    // Toggle the add contact dropdown
    if (addContactDropdown.style.display === 'none' || addContactDropdown.style.display === '') {
        addContactDropdown.style.display = 'block';
    } else {
        addContactDropdown.style.display = 'none';
    }
}

function toggleSearchContainer() {
    var searchContainer = document.getElementById('search-container');
    var userDropdown = document.getElementById('userDropdown');
    var addContactDropdown = document.getElementById('addContactDropdown');
    var searchMessageInput = document.getElementById('searchMessage');

    if (userDropdown.style.display === 'block') {
        userDropdown.style.display = 'none';
    }
    if (addContactDropdown.style.display === 'block') {
        addContactDropdown.style.display = 'none';
    }

    if (searchContainer.style.display === 'none' || searchContainer.style.display === '') {
        searchContainer.style.display = 'block';
        if (searchMessageInput) {
            searchMessageInput.value = '';
        }

        const searchMessages = document.querySelectorAll('.Searchmessage.individual-message');
        searchMessages.forEach(message => message.remove());
    } else {
        searchContainer.style.display = 'none';
    }
}

function logout() {
    clearUserConversations();
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
        updateStoredConversations(contactName);

        conversationList.style.display = 'none'; 
        conversationList.offsetHeight; 
        conversationList.style.display = 'block'; 

        selectConversation(newConversation);
    } else {
        selectConversation(exists);
    }
    
    document.getElementById('errorMessage').style.display = 'none'; 
    document.getElementById('addContactDropdown').style.display = 'none'; 
}

function selectConversation(element) {
    if (!element) {
        return;
    }
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

                if (senderId === peerId) {
                    // Message sent from this user
                    messageElement.classList.add('sent');
                    messageElement.innerHTML = `
                        <p>${messageContent}</p>
                        <span class="timestamp">${fullTimestamp}</span>
                    `;
                } else {
                    // Message received from another peer
                    messageElement.classList.add('received');
                    messageElement.innerHTML = `
                        <span class="sender">${senderId}</span>
                        <p>${messageContent}</p>
                        <span class="timestamp">${fullTimestamp}</span>
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

function getLocalStorageKey() {
    var urlParams = new URLSearchParams(window.location.search);
    var peerId = urlParams.get('peerId');
    return `conversations_${peerId}`;
}

function updateStoredConversations(contactName) {
    const storageKey = getLocalStorageKey();
    const storedConversations = JSON.parse(localStorage.getItem(storageKey) || '[]');

    if (!storedConversations.includes(contactName)) {
        storedConversations.push(contactName);
        localStorage.setItem(storageKey, JSON.stringify(storedConversations));
    }
}

function restoreConversations() {
    const storageKey = getLocalStorageKey();
    const storedConversations = JSON.parse(localStorage.getItem(storageKey) || '[]');
    const conversationList = document.querySelector('.conversation-list');

    conversationList.innerHTML = '';

    storedConversations.forEach(contactName => {
        var newConversation = document.createElement('li');
        newConversation.classList.add('conversation-container');
        newConversation.setAttribute('data-contact', contactName);
        newConversation.innerHTML = '<img src="/images/user.png"> ' + contactName;

        newConversation.onclick = function () {
            selectConversation(newConversation);
        };

        conversationList.appendChild(newConversation);
    });
}

document.addEventListener('DOMContentLoaded', function () {
    restoreConversations();
});
function clearUserConversations() {
    const storageKey = getLocalStorageKey();
    localStorage.removeItem(storageKey);
}

function searchMessage() {
    const searchMessageInput = document.getElementById('searchMessage');
    const searcMessage = searchMessageInput.value.trim();
    const searchMessagesContainer = document.querySelector('.search-messages');
    searchMessagesContainer.innerHTML = '';

    if(searcMessage) {
        var urlParams = new URLSearchParams(window.location.search);
        var peerId = urlParams.get('peerId');
        fetch('/searchMessage?peerId=' + peerId + '&searchMessage=' + searcMessage, {
            method: 'POST',
        })
        .then(response => response.json())
        .then(messagesFound => {
            messagesFound.forEach(message => {
                const messageElement = document.createElement('div');
                messageElement.classList.add('Searchmessage');

                const [timestampAndSender, messageContent] = message.split('] ');
                const [fullTimestamp, sender] = timestampAndSender.split('-[');
                const senderandreceiverId = sender.replace('[', '').replace(']', '');
                var [senderId, receiverId] = senderandreceiverId.split(',');

                
                if(senderId == peerId) {
                    senderId = "Myself";
                }

                if(senderId != "Myself") {
                    messageElement.classList.add('individual-message'); 
                    messageElement.innerHTML = `
                        <span><strong>${senderId}</strong></span>
                        <p>${messageContent}</p>
                        <span class="timestamp">${fullTimestamp}</span>
                    `;
                } else {
                    messageElement.classList.add('individual-message'); 
                    messageElement.innerHTML = `
                        <span><strong>${senderId}</strong> to <strong>${receiverId}</strong></span>
                        <p>${messageContent}</p>
                        <span class="timestamp">${fullTimestamp}</span>
                    `;
                }


                searchMessagesContainer.appendChild(messageElement);
            });
            searchMessagesContainer.scrollTop = searchMessagesContainer.scrollHeight;
        })
        .catch(error => {
            console.error('Error:', error);
        });

    }
}

function populateContacts(contacts) {
    var conversationList = document.querySelector('.conversation-list');    

    conversationList.innerHTML = '';

    contacts.forEach(function(contactName) {
        var newConversation = document.createElement('li');
        newConversation.classList.add('conversation-container');
        newConversation.setAttribute('data-contact', contactName);
        newConversation.innerHTML = '<img src="/images/user.png">' + contactName;

        newConversation.onclick = function() {
            selectConversation(newConversation);
        };

        conversationList.appendChild(newConversation);
        updateStoredConversations(contactName);

        conversationList.style.display = 'none'; 
        conversationList.offsetHeight; 
        conversationList.style.display = 'block'; 
    });

}

// Initial check on page load
document.addEventListener('DOMContentLoaded', toggleChatPanel);