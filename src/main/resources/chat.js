// Ensure user is authenticated and assign unique session ID to each tab
if (!localStorage.getItem("isAuthenticated")) {
  window.location.href = "index.html"; // Redirect if not authenticated
}

const username = localStorage.getItem("username");
const userSessionId = sessionStorage.getItem("userSessionId");
if (!userSessionId) {
  console.error("Session ID is missing. Redirecting to login page.");
  window.location.href = "index.html";
} else {
  sessionStorage.setItem("userSessionId", userSessionId); // Save session ID
}

let ws; // Declare WebSocket globally
let wsInstanceId = 0; // Track the current WebSocket instance
const messageInput = document.getElementById("message");
const chatBox = document.getElementById("chat-box");
const statusMessage = document.getElementById("status-message");
const chatList = document.getElementById("chat-list");
const fileInput = document.getElementById("file-input");
const mediaButton = document.getElementById("media-button");
const mediaPreview = document.getElementById("media-preview");
let selectedFile = null;

const sidebarAvatar = document.getElementById("sidebar-avatar");
if (sidebarAvatar) {
  const username = localStorage.getItem("username");
  fetch(`/getProfilePicture?username=${encodeURIComponent(username)}`)
    .then((response) => response.json())
    .then((data) => {
      sidebarAvatar.src =
        data.profilePicture || "/static/avatars/default-avatar.png";
    })
    .catch((error) => {
      console.error("Error fetching profile picture:", error);
      sidebarAvatar.src = "/static/avatars/default-avatar.png"; // Fallback to default avatar
    });
}

let isWebSocketOpen = false;

// Open file explorer when the media button is clicked
mediaButton.addEventListener("click", () => {
  fileInput.click();
});

// Handle file selection
fileInput.addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;

  selectedFile = file;

  // Clear previous preview
  mediaPreview.innerHTML = "";
  mediaPreview.style.display = "block";

  // Create a preview for the selected file
  const fileType = file.type.split("/")[0];
  if (fileType === "image") {
    const img = document.createElement("img");
    img.src = URL.createObjectURL(file);
    img.style.maxWidth = "200px";
    img.style.maxHeight = "200px";
    mediaPreview.appendChild(img);
  } else if (fileType === "video") {
    const video = document.createElement("video");
    video.src = URL.createObjectURL(file);
    video.controls = true;
    video.style.maxWidth = "200px";
    video.style.maxHeight = "200px";
    video.preload = "metadata"; // Load metadata for the video
    mediaPreview.appendChild(video);
  }
});

// Handle send button click
document.getElementById("send-button").addEventListener("click", async () => {
  const message = messageInput.value.trim();
  const chatId = sessionStorage.getItem("selectedChatId");
  const groupId = sessionStorage.getItem("selectedGroupId");

  if (!chatId && !groupId) {
    showFeedback("No chat selected.", "error");
    return;
  }

  if (selectedFile) {
    // Upload the file
    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("/upload", {
        method: "POST",
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        const fileUrl = data.fileUrl;

        // Send the file URL as a message
        sendMessage(fileUrl, "file");
      } else {
        console.error("Failed to upload file");
        showFeedback("Failed to upload file.", "error");
      }
    } catch (error) {
      console.error("Error uploading file:", error);
      showFeedback("Error uploading file.", "error");
    }

    // Clear the file input and preview
    selectedFile = null;
    mediaPreview.innerHTML = "";
    mediaPreview.style.display = "none";
  }

  if (message) {
    // Send the text message
    sendMessage(message, "text", chatId, groupId);
  }

  messageInput.value = ""; // Clear the input field
});

// Function to send a message
function sendMessage(content, type = "text") {
  const sessionId = sessionStorage.getItem("userSessionId");
  const chatId = sessionStorage.getItem("selectedChatId"); // Use sessionStorage for chatId
  const groupId = sessionStorage.getItem("selectedGroupId"); // Use sessionStorage for groupId
  console.log(
    "Sending message with sessionId:",
    sessionId,
    "and chatId:",
    chatId,
    "and groupId:",
    groupId
  );

  const message = {
    type: "message",
    sessionId: sessionId,
    username: localStorage.getItem("username"),
    message: content,
    messageType: type,
    chatId: chatId,
    groupId: groupId,
  };

  ws.send(JSON.stringify(message));
}

let isLoadingMessages = false; // Flag to track if messages are being loaded

// Function to load messages for a specific DM or group chat
// Supports pagination with limit and offset
async function loadMessages(
  id,
  limit = 20,
  offset = 0,
  clearChatBox = false,
  isGroup // Add a flag to differentiate between DMs and group chats
) {
  if (isLoadingMessages) {
    console.log(
      "Message load already in progress. Skipping duplicate request."
    );
    return; // Prevent duplicate requests
  }

  isLoadingMessages = true; // Set the flag to true

  try {
    // Determine the endpoint based on whether it's a group chat or DM
    const endpoint = isGroup ? "/loadGroupMessages" : "/loadMessages";
    console.log(
      `${endpoint}?${
        isGroup ? "groupId" : "chatId"
      }=${id}&limit=${limit}&offset=${offset}`
    );

    const response = await fetch(
      `${endpoint}?${
        isGroup ? "groupId" : "chatId"
      }=${id}&limit=${limit}&offset=${offset}`
    );

    if (response.ok) {
      let messages = await response.json();

      if (clearChatBox) {
        messages.reverse();
        chatBox.innerHTML = "";
        let previousTimestamp = null;
        messages.forEach((msg) => {
          const currentTimestamp = new Date(msg.timestamp);
          let showDivider = false;
          if (
            !previousTimestamp ||
            Math.abs(currentTimestamp - previousTimestamp) / 60000 > 30
          ) {
            showDivider = true;
          }
          if (showDivider) insertDateDivider(currentTimestamp, false);
          const messageType = msg.username === username ? "sent" : "received";
          showMessage(
            msg.message,
            messageType,
            msg.username,
            msg.messageType,
            false,
            msg.messageId
          );
          previousTimestamp = currentTimestamp;
        });
      } else {
        // Collect message and divider "objects" in an array
        let previousTimestamp = null;
        const items = [];
        for (let i = messages.length - 1; i >= 0; i--) {
          const msg = messages[i];
          const currentTimestamp = new Date(msg.timestamp);
          let showDivider = false;
          if (
            !previousTimestamp ||
            Math.abs(previousTimestamp - currentTimestamp) / 60000 > 30
          ) {
            showDivider = true;
          }
          if (showDivider) {
            items.push({
              type: "divider",
              timestamp: currentTimestamp,
            });
          }
          items.push({
            type: "message",
            msg,
          });
          previousTimestamp = currentTimestamp;
        }

        // Now reverse and render
        items.reverse().forEach((item) => {
          if (item.type === "divider") {
            insertDateDivider(item.timestamp, true); // prepend=true is fine, since we're going in order now
          } else if (item.type === "message") {
            const msg = item.msg;
            const messageType = msg.username === username ? "sent" : "received";
            showMessage(
              msg.message,
              messageType,
              msg.username,
              msg.messageType,
              true,
              msg.messageId
            );
          }
        });
      }
      console.log(messages.map((m) => m.messageId || m.timestamp));
    } else {
      console.error(
        `Failed to load messages for ${isGroup ? "group" : "chat"}:`,
        id
      );
    }
  } catch (error) {
    console.error(
      `Error loading messages for ${isGroup ? "group" : "chat"}:`,
      error
    );
  } finally {
    isLoadingMessages = false; // Reset the flag after the request completes
  }
}

// Function to show feedback messages (WebSocket errors, etc.)
function showFeedback(message, type) {
  const feedbackMessage = document.createElement("div");
  feedbackMessage.textContent = message;
  feedbackMessage.style.padding = "10px";
  feedbackMessage.style.margin = "5px 0";
  feedbackMessage.style.borderRadius = "5px";
  feedbackMessage.style.color = "#fff";

  if (type === "success") {
    feedbackMessage.style.backgroundColor = "#28a745"; // Green for success
  } else {
    feedbackMessage.style.backgroundColor = "#dc3545"; // Red for error
  }

  chatBox.appendChild(feedbackMessage);
  chatBox.scrollTop = chatBox.scrollHeight; // Auto-scroll to the bottom
}

// Function to show user messages in the chatbox with usernames
async function showMessage(
  content,
  type,
  sender,
  messageType,
  prepend = false,
  messageId = null // Add messageId for deletion
) {
  const messageContainer = document.createElement("div");
  messageContainer.classList.add("message-container", type);

  if (type === "received") {
    const profilePic = document.createElement("img");
    profilePic.classList.add("profile-pic");
    profilePic.alt = `${sender}'s profile picture`;
    profilePic.src = "/static/avatars/default-avatar.png"; // Set default avatar initially

    // Append the profile picture immediately
    messageContainer.appendChild(profilePic);

    // Load the profile picture asynchronously
    fetchProfilePicture(sender)
      .then((profilePicUrl) => {
        profilePic.src = profilePicUrl;
      })
      .catch((error) => {
        console.error("Error fetching profile picture:", error);
      });
  }

  const messageContent = document.createElement("div");
  messageContent.classList.add("message-content");

  const senderName = document.createElement("div");
  senderName.classList.add("message-sender");
  senderName.textContent = sender;

  const messageDiv = document.createElement("div");
  messageDiv.classList.add("message", type);

  if (messageType === "file") {
    if (!content) {
      console.error("File content is undefined");
      return;
    }

    const fileType = content.split(".").pop();
    if (["png", "jpg", "jpeg", "gif", "avif", "jfif"].includes(fileType)) {
      const img = document.createElement("img");
      img.src = content;
      img.style.maxWidth = "200px";
      img.style.maxHeight = "200px";
      messageDiv.appendChild(img);
    } else if (["mp4", "webm", "ogg", "mkv", "avi", "mov"].includes(fileType)) {
      // Create a placeholder for the video
      const placeholder = document.createElement("div");
      placeholder.textContent = "Click to load video";
      placeholder.style.cursor = "pointer";
      placeholder.style.padding = "10px";
      placeholder.style.border = "1px solid #ccc";
      placeholder.style.color = "#555";
      placeholder.style.textAlign = "center";
      placeholder.style.backgroundColor = "#f9f9f9";

      // Add a click event to load the video
      placeholder.addEventListener("click", () => {
        const video = document.createElement("video");
        video.src = content;
        video.controls = true;
        video.style.maxWidth = "200px";
        video.style.maxHeight = "200px";

        // Replace the placeholder with the video
        placeholder.replaceWith(video);
      });

      messageDiv.appendChild(placeholder);
    } else {
      const link = document.createElement("a");
      link.href = content;
      link.textContent = "Download File";
      link.target = "_blank";
      messageDiv.appendChild(link);
    }
  } else {
    messageDiv.textContent = content || "Message content is missing";
  }

  // Add delete functionality for sent messages
  if (type === "sent") {
    const menuButton = document.createElement("div");
    menuButton.classList.add("message-menu");
    menuButton.textContent = "⋮";

    const deleteMenu = document.createElement("div");
    deleteMenu.classList.add("delete-menu");
    deleteMenu.textContent = "Delete Message";
    deleteMenu.style.display = "none";

    // Show the delete menu when the three-dot menu is clicked
    menuButton.addEventListener("click", () => {
      deleteMenu.style.display =
        deleteMenu.style.display === "none" ? "block" : "none";
    });

    // Hide the delete menu when clicking outside
    document.addEventListener("click", (event) => {
      if (
        !menuButton.contains(event.target) &&
        !deleteMenu.contains(event.target)
      ) {
        deleteMenu.style.display = "none";
      }
    });

    // Handle message deletion
    deleteMenu.addEventListener("click", async () => {
      if (confirm("Are you sure you want to delete this message?")) {
        try {
          const response = await fetch(`/deleteMessage`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ messageId }),
          });

          if (response.ok) {
            messageContainer.remove(); // Remove the message from the chatbox
            alert("Message deleted successfully.");
          } else {
            alert("Failed to delete the message.");
          }
        } catch (error) {
          console.error("Error deleting message:", error);
          alert("An error occurred while deleting the message.");
        }
      }
    });

    messageContainer.appendChild(menuButton);
    messageContainer.appendChild(deleteMenu);
  }

  // Append sender name and message to the wrapper
  messageContent.appendChild(senderName);
  messageContent.appendChild(messageDiv);

  // Append the wrapper to the message container
  messageContainer.appendChild(messageContent);

  if (prepend) {
    chatBox.insertBefore(messageContainer, chatBox.firstChild);
  } else {
    chatBox.appendChild(messageContainer);
  }

  if (!prepend) {
    chatBox.scrollTop = chatBox.scrollHeight; // Auto-scroll to the bottom
  }
}

const backToSidebarButton = document.getElementById("back-to-sidebar");
const chatSidebar = document.querySelector(".chat-sidebar");
const chatMain = document.querySelector(".chat-main");
const groupHeader = document.getElementById("group-header");
const groupNameDisplay = document.getElementById("group-name-display");
const groupInfoBtn = document.getElementById("group-info-btn");
const groupInfoModal = document.getElementById("group-info-modal");
const closeGroupInfoModal = document.getElementById("close-group-info-modal");
const groupMembersList = document.getElementById("group-members-list");
const groupOwnerActions = document.getElementById("group-owner-actions");
const addMemberBtn = document.getElementById("add-member-btn");

let currentGroupId = null;
let isGroupOwner = false;

// Elements
const addMemberSection = document.getElementById("add-member-section");
const addMemberSearch = document.getElementById("add-member-search");
const addMemberSearchResults = document.getElementById(
  "add-member-search-results"
);

// Show add member UI when owner clicks "Add Member"
addMemberBtn.addEventListener("click", () => {
  addMemberSection.style.display = "block";
  addMemberSearch.value = "";
  addMemberSearchResults.innerHTML = "";
  addMemberSearch.focus();
});

// Search users as you type
addMemberSearch.addEventListener("input", async (event) => {
  const searchTerm = event.target.value.trim();
  if (!searchTerm) {
    addMemberSearchResults.innerHTML = "";
    return;
  }
  const response = await fetch(
    `/searchUsers?q=${encodeURIComponent(searchTerm)}`
  );
  if (response.ok) {
    const users = await response.json();
    addMemberSearchResults.innerHTML = "";
    users.forEach((user) => {
      // Don't show users already in the group
      if (
        [...groupMembersList.children].some((li) =>
          li.textContent.trim().startsWith(user.username)
        )
      )
        return;
      const li = document.createElement("li");
      li.textContent = user.username;
      li.addEventListener("click", async () => {
        // Add member via backend
        await fetch("/addGroupMember", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Session-Id": sessionStorage.getItem("userSessionId"),
          },
          body: JSON.stringify({
            groupId: currentGroupId,
            username: user.username,
          }),
        });
        await renderGroupMembers(); // Refresh list after adding
        addMemberSection.style.display = "none";
      });
      addMemberSearchResults.appendChild(li);
    });
  }
});

// Function to handle chat selection
async function selectChat(id, isGroup) {
  // Clear previous chat state
  sessionStorage.removeItem("selectedChatId");
  sessionStorage.removeItem("selectedGroupId");

  if (isGroup) {
    sessionStorage.setItem("selectedGroupId", id); // Store the selected group ID
    console.log("Selected group ID:", id);

    // Find the group name of the chat
    const chatItem = document.querySelector(`[data-group-id="${id}"]`);
    let groupName = "Unknown Group";
    if (chatItem) {
      // If the group name is followed by an unread badge, exclude it
      groupName = chatItem.childNodes[0].nodeValue.trim();
    }

    // Hide the placeholder and show the chat box and input area
    document.getElementById("placeholder").style.display = "none";
    document.getElementById("chat-box").style.display = "block";
    document.getElementById("message-input").style.display = "flex";

    // Load group messages
    loadMessages(id, 20, 0, true, true);

    groupHeader.style.display = "flex";
    groupNameDisplay.textContent = groupName;
    currentGroupId = id;

    // Optionally, check if current user is group owner
    const response = await fetch(`/getGroupInfo?groupId=${id}`);
    if (response.ok) {
      const data = await response.json();
      isGroupOwner = data.owner === localStorage.getItem("username");
    }
  } else {
    sessionStorage.setItem("selectedChatId", id); // Store the selected chat ID in sessionStorage
    console.log("Selected chat ID:", id);

    // Hide the placeholder and show the chat box and input area
    document.getElementById("placeholder").style.display = "none";
    document.getElementById("chat-box").style.display = "block";
    document.getElementById("message-input").style.display = "flex";

    // Load the first 20 messages for the selected chat
    loadMessages(id, 20, 0, true, false);

    groupHeader.style.display = "none";
    currentGroupId = null;
    isGroupOwner = false;
  }

  // Mark messages as read
  try {
    await fetch("/markMessagesAsRead", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Session-Id": sessionStorage.getItem("userSessionId"), // <-- Add this line
      },
      body: JSON.stringify({ id, isGroup }),
    });
  } catch (error) {
    console.error("Error marking messages as read:", error);
  }

  console.log("Selected chatId:", sessionStorage.getItem("selectedChatId"));
  console.log("Selected groupId:", sessionStorage.getItem("selectedGroupId"));

  // Show the chat area and hide the sidebar on mobile
  if (window.innerWidth <= 768) {
    chatSidebar.style.display = "none"; // Hide the sidebar
    chatMain.style.display = "flex"; // Show the chat area
    chatMain.classList.add("active"); // Mark chat-main as active
    backToSidebarButton.style.display = "block";
    backToSidebarButton.classList.add("active"); // Show the back button
  }

  // Close any existing WebSocket connection
  if (ws) {
    ws.onmessage = null;
    ws.onclose = null; // Remove old handler
    ws.close();
  }

  // Increment the instance ID for the new connection
  wsInstanceId++;
  const thisWsInstance = wsInstanceId;

  // Fetch the WebSocket URL from config.json
  fetch("/config.json")
    .then((response) => {
      if (!response.ok) {
        throw new Error("Failed to load configuration");
      }
      return response.json();
    })
    .then((config) => {
      const websocketUrl = config.websocketUrl || "ws://localhost:8081";

      // Establish a new WebSocket connection
      ws = new WebSocket(websocketUrl);

      ws.onopen = () => {
        console.log("Connected to WebSocket server for chat ID:", id);

        // Send authentication message
        const sessionId = sessionStorage.getItem("userSessionId");
        console.log(
          "Sending authentication message with sessionId:",
          sessionId
        );
        ws.send(
          JSON.stringify({
            type: "authenticate",
            sessionId: sessionId,
            username: localStorage.getItem("username"),
          })
        );

        // Send chat selection message

        const messageData = {
          type: "selectChat",
          sessionId: sessionId,
          username: localStorage.getItem("username"),
        };

        if (isGroup) {
          console.log("Sending selectChat message with groupId:", id);
          messageData.groupId = id; // Set groupId for group chats
        } else {
          console.log("Sending selectChat message with chatId:", id);
          messageData.chatId = id; // Set chatId for DMs
        }

        console.log("Sending selectChat message:", messageData);
        // Send the selectChat message to the WebSocket server
        ws.send(JSON.stringify(messageData));
      };

      ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        showFeedback("WebSocket connection error.", "error");
      };

      ws.onclose = (event) => {
        if (thisWsInstance === wsInstanceId) {
          console.log(
            "Disconnected from WebSocket server for chat ID:",
            id,
            event
          );
          showFeedback("Disconnected from WebSocket.", "error");
        }
      };

      ws.onmessage = (event) => {
        if (!event.data) {
          console.error("Received empty message");
          showFeedback("Received empty message.", "error");
          return;
        }

        try {
          const messageData = JSON.parse(event.data);

          if (messageData.type === "message") {
            showMessage(
              messageData.message,
              messageData.username === username ? "sent" : "received",
              messageData.username,
              messageData.messageType,
              false,
              messageData.messageId // Pass messageId for deletion
            );
          }
        } catch (error) {
          console.error("Error parsing message:", error);
          showFeedback("Error receiving message.", "error");
        }
      };
    })
    .catch((error) => {
      console.error("Error loading configuration:", error);
      showFeedback("Failed to load configuration.", "error");
    });
}

// Back button logic for mobile
backToSidebarButton.addEventListener("click", () => {
  chatSidebar.style.display = "block"; // Show the sidebar
  chatMain.style.display = "none"; // Hide the chat area
  chatMain.classList.remove("active"); // Remove active class from chat-main
  backToSidebarButton.classList.remove("active"); // Hide the back button
});

// Open group info modal
groupInfoBtn.addEventListener("click", async () => {
  if (!currentGroupId) return;
  groupInfoModal.style.display = "flex";
  await renderGroupMembers();
});

// Close modal
closeGroupInfoModal.addEventListener("click", () => {
  groupInfoModal.style.display = "none";
});
window.addEventListener("click", (event) => {
  if (event.target === groupInfoModal) groupInfoModal.style.display = "none";
});

const profilePictureCache = {};

async function fetchProfilePicture(username) {
  if (profilePictureCache[username]) {
    return profilePictureCache[username];
  }

  try {
    const response = await fetch(
      `/getProfilePicture?username=${encodeURIComponent(username)}`
    );
    if (response.ok) {
      const data = await response.json();
      const profilePicture =
        data.profilePicture || "/static/avatars/default-avatar.png";
      profilePictureCache[username] = profilePicture; // Cache the result
      return profilePicture;
    } else {
      console.error("Failed to fetch profile picture for user:", username);
      return "/static/avatars/default-avatar.png"; // Fallback to default avatar
    }
  } catch (error) {
    console.error("Error fetching profile picture:", error);
    return "/static/avatars/default-avatar.png"; // Fallback to default avatar
  }
}

// Function to load chats and populate the sidebar
async function loadChats() {
  try {
    const response = await fetch("/loadChats", {
      method: "GET",
      headers: {
        Username: localStorage.getItem("username"), // Add the Username header
      },
    });

    if (response.ok) {
      const chats = await response.json();

      const chatList = document.getElementById("chat-list");
      chatList.innerHTML = ""; // Clear previous chats

      // Add chats to the list
      chats.forEach((chat) => {
        const chatItem = document.createElement("li");
        chatItem.textContent = chat.name; // Display the chat name
        chatItem.dataset.chatId = chat.id; // Store chat ID for DMs
        chatItem.dataset.groupId = chat.id; // For groups
        chatItem.dataset.chatType = chat.type; // Store chat type ("dm" or "group")
        chatItem.classList.add(chat.type === "dm" ? "dm-item" : "group-item"); // Add a class for styling

        // Add unread message count
        if (chat.unreadCount > 0) {
          const unreadBadge = document.createElement("span");
          unreadBadge.classList.add("unread-badge");
          unreadBadge.textContent = chat.unreadCount; // Display unread count
          chatItem.appendChild(unreadBadge);
        }

        chatItem.addEventListener("click", () => {
          selectChat(chat.id, chat.type === "group"); // Handle chat selection
        });

        chatList.appendChild(chatItem);
      });
    } else {
      console.error("Failed to load chats");
    }
  } catch (error) {
    console.error("Error loading chats:", error);
  }
}

// Ensure no chat is selected by default
document.addEventListener("DOMContentLoaded", () => {
  localStorage.removeItem("selectedChatId"); // Clear any previously selected chat
  loadChats();
});

chatBox.addEventListener("scroll", () => {
  if (chatBox.scrollTop === 0) {
    const chatId = sessionStorage.getItem("selectedChatId");
    const groupId = sessionStorage.getItem("selectedGroupId");
    const currentMessageCount =
      chatBox.querySelectorAll(".message-container").length;

    if (groupId) {
      // Load older messages for a group chat
      loadMessages(groupId, 20, currentMessageCount, false, true);
    } else if (chatId) {
      // Load older messages for a DM
      loadMessages(chatId, 20, currentMessageCount, false, false);
    } else {
      console.error("No chat or group selected.");
    }
  }
});

const userSearchInput = document.getElementById("user-search");
const searchResults = document.getElementById("search-results");

userSearchInput.addEventListener("input", async (event) => {
  const searchTerm = event.target.value.trim();

  if (!searchTerm) {
    if (searchResults) {
      searchResults.style.display = "none";
      searchResults.innerHTML = "";
    }
    return;
  }

  try {
    const response = await fetch(
      `/searchUsers?q=${encodeURIComponent(searchTerm)}`
    );
    if (response.ok) {
      const users = await response.json();
      if (searchResults) {
        searchResults.innerHTML = ""; // Clear previous results
        searchResults.style.display = "block";

        users.forEach((user) => {
          const userItem = document.createElement("li");
          userItem.textContent = user.username;
          userItem.addEventListener("click", () => {
            startNewChat(user.username);
            searchResults.style.display = "none"; // Hide results after selection
          });
          searchResults.appendChild(userItem);
        });
      }
    } else {
      console.error("Failed to search for users");
    }
  } catch (error) {
    console.error("Error searching for users:", error);
  }
});

// Function to start a new chat
async function startNewChat(otherUsername) {
  try {
    const response = await fetch("/startChat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: localStorage.getItem("username"),
        otherUsername,
      }),
    });

    if (response.ok) {
      const chatData = await response.json();
      const chatId = chatData.chatId;

      // Add the new chat to the sidebar
      const chatItem = document.createElement("li");
      chatItem.textContent = otherUsername;
      chatItem.dataset.chatId = chatId;
      chatItem.addEventListener("click", () => {
        selectChat(chatId);
      });
      chatList.appendChild(chatItem);

      // Select the new chat
      selectChat(chatId);
    } else {
      console.error("Failed to start a new chat");
    }
  } catch (error) {
    console.error("Error starting a new chat:", error);
  }
}

const searchToggle = document.getElementById("search-toggle");
const searchBar = document.getElementById("search-bar");

searchToggle.addEventListener("click", () => {
  if (searchBar.style.display === "none") {
    searchBar.style.display = "block";
  } else {
    searchBar.style.display = "none";
  }
});

const sidebarUsername = document.getElementById("sidebar-username");
if (sidebarUsername) {
  sidebarUsername.textContent = username; // Set the logged-in username
}

// Get modal elements
const profileModal = document.getElementById("profile-modal");
const closeModal = document.getElementById("close-modal");
const profileSettingsButton = document.getElementById("profile-settings");
const saveProfileButton = document.getElementById("save-profile");
const logoutButton = document.getElementById("logout-button");
const profilePicInput = document.getElementById("profile-pic");
const profilePicPreview = document.getElementById("profile-pic-preview");
const editUsernameInput = document.getElementById("edit-username");
const editPasswordInput = document.getElementById("edit-password");
const removeProfilePicButton = document.getElementById("remove-profile-pic");

removeProfilePicButton.addEventListener("click", async () => {
  const confirmRemoval = confirm(
    "Are you sure you want to remove your profile picture?"
  );
  if (!confirmRemoval) return;

  const formData = new FormData();
  formData.append("removeProfilePic", "true"); // Add the removeProfilePic field

  try {
    const response = await fetch("/updateProfile", {
      method: "POST",
      headers: {
        "Session-Id": sessionStorage.getItem("userSessionId"), // Include the Session-Id header
      },
      body: formData, // Send the form data
    });

    if (response.ok) {
      alert("Profile picture removed successfully!");
      profilePicPreview.src = "/static/avatars/default-avatar.png"; // Reset to default avatar
      sidebarAvatar.src = "/static/avatars/default-avatar.png"; // Update the sidebar avatar
    } else {
      alert("Failed to remove profile picture.");
    }
  } catch (error) {
    console.error("Error removing profile picture:", error);
    alert("An error occurred while removing your profile picture.");
  }
});

// Open the modal when the gear icon is clicked
profileSettingsButton.addEventListener("click", async () => {
  profileModal.style.display = "flex";

  // Fetch and display the current profile picture
  const username = localStorage.getItem("username");
  try {
    const response = await fetch(
      `/getProfilePicture?username=${encodeURIComponent(username)}`
    );
    if (response.ok) {
      const data = await response.json();
      profilePicPreview.src =
        data.profilePicture || "/static/avatars/default-avatar.png";
    } else {
      console.error("Failed to fetch profile picture.");
      profilePicPreview.src = "/static/avatars/default-avatar.png"; // Fallback to default avatar
    }
  } catch (error) {
    console.error("Error fetching profile picture:", error);
    profilePicPreview.src = "/static/avatars/default-avatar.png"; // Fallback to default avatar
  }
});

// Close the modal when the close button is clicked
closeModal.addEventListener("click", () => {
  profileModal.style.display = "none";
});

// Close the modal when clicking outside the modal content
window.addEventListener("click", (event) => {
  if (event.target === profileModal) {
    profileModal.style.display = "none";
  }
});

// Preview the selected profile picture
profilePicInput.addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (file) {
    profilePicPreview.src = URL.createObjectURL(file);
  }
});

// Save profile changes or password change
function handleProfileSaveOrPasswordChange() {
  const newUsername = editUsernameInput.value.trim();
  const oldPassword = document.getElementById("old-password").value.trim();
  const newPassword = editPasswordInput.value.trim();
  const confirmPassword = document
    .getElementById("confirm-password")
    .value.trim();
  const profilePic = profilePicInput.files[0];

  // If the password tab is active, validate password fields
  if (passwordTab.classList.contains("active")) {
    if (!oldPassword) {
      alert("Please enter your old password.");
      return;
    }
    if (!newPassword) {
      alert("Please enter a new password.");
      return;
    }
    if (newPassword !== confirmPassword) {
      alert("New password and confirmation do not match.");
      return;
    }
  }

  const formData = new FormData();
  if (newUsername && profileTab.classList.contains("active"))
    formData.append("username", newUsername);
  if (oldPassword && passwordTab.classList.contains("active"))
    formData.append("oldPassword", oldPassword);
  if (newPassword && passwordTab.classList.contains("active"))
    formData.append("newPassword", newPassword);
  if (profilePic && profileTab.classList.contains("active"))
    formData.append("profilePic", profilePic);

  fetch("/updateProfile", {
    method: "POST",
    body: formData,
    headers: {
      "Session-Id": sessionStorage.getItem("userSessionId"),
    },
  })
    .then(async (response) => {
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          alert("Profile updated successfully!");
          if (newUsername) {
            document.getElementById("sidebar-username").textContent =
              newUsername;
          }
          if (profilePic) {
            const avatarUrl = URL.createObjectURL(profilePic);
            document.getElementById("sidebar-avatar").src = avatarUrl;
          }
          profileModal.style.display = "none";
        } else {
          alert("Failed to update profile: " + data.error);
        }
      } else {
        alert("Failed to update profile.");
      }
    })
    .catch((error) => {
      console.error("Error updating profile:", error);
      alert("An error occurred while updating your profile.");
    });
}

// Attach the same handler to both buttons
saveProfileButton.addEventListener("click", handleProfileSaveOrPasswordChange);
document
  .getElementById("change-password-btn")
  .addEventListener("click", handleProfileSaveOrPasswordChange);

// Log out the user
logoutButton.addEventListener("click", () => {
  localStorage.clear();
  sessionStorage.clear();
  window.location.href = "index.html"; // Redirect to login page
});

// Open the "Create Group" modal
const createGroupButton = document.getElementById("create-group-button");
const createGroupModal = document.getElementById("create-group-modal");
const closeGroupModal = document.getElementById("close-group-modal");
const groupMembersSearch = document.getElementById("group-members-search");
const groupMembersSearchResults = document.getElementById(
  "group-members-search-results"
);
const addedMembersList = document.getElementById("added-members-list");
const createGroupSubmit = document.getElementById("create-group-submit");

// Store added members
const addedMembers = new Set();

// Open the "Create Group" modal
createGroupButton.addEventListener("click", () => {
  createGroupModal.style.display = "flex";

  // Automatically add the current user to the "added members" list
  const currentUser = localStorage.getItem("username");
  if (currentUser && !addedMembers.has(currentUser)) {
    addMemberToList(currentUser, true); // Automatically add the creator
  }
});

// Close the modal
closeGroupModal.addEventListener("click", () => {
  createGroupModal.style.display = "none";
  groupMembersSearch.value = "";
  groupMembersSearchResults.innerHTML = "";
  addedMembersList.innerHTML = "";
  addedMembers.clear();
});

// Search for users
groupMembersSearch.addEventListener("input", async (event) => {
  const searchTerm = event.target.value.trim();

  if (!searchTerm) {
    groupMembersSearchResults.innerHTML = ""; // Just clear, don't hide
    return;
  }

  try {
    const response = await fetch(
      `/searchUsers?q=${encodeURIComponent(searchTerm)}`
    );
    if (response.ok) {
      const users = await response.json();
      groupMembersSearchResults.innerHTML = ""; // Clear previous results

      users.forEach((user) => {
        if (!addedMembers.has(user.username)) {
          const userItem = document.createElement("li");
          userItem.textContent = user.username;
          userItem.addEventListener("click", () => {
            addMemberToList(user.username, false, user.id);
            groupMembersSearchResults.innerHTML = ""; // Clear after selection
            groupMembersSearch.value = "";
          });
          groupMembersSearchResults.appendChild(userItem);
        }
      });
    } else {
      groupMembersSearchResults.innerHTML = "";
    }
  } catch (error) {
    groupMembersSearchResults.innerHTML = "";
  }
});

// Add a user to the "added members" list
function addMemberToList(username, isCreator, userId = null) {
  addedMembers.add(username);

  const memberItem = document.createElement("li");
  memberItem.textContent = username;

  if (!isCreator) {
    const removeButton = document.createElement("button");
    removeButton.textContent = "Remove";
    removeButton.classList.add("remove-member");

    // Remove the user from the list when the button is clicked
    removeButton.addEventListener("click", () => {
      addedMembers.delete(username);
      memberItem.remove();
    });

    memberItem.appendChild(removeButton);
  } else {
    memberItem.textContent += " (You)";
  }

  addedMembersList.appendChild(memberItem);
}

// Handle group creation
createGroupSubmit.addEventListener("click", async () => {
  const groupName = document.getElementById("group-name").value.trim();
  const selectedMembers = Array.from(addedMembers).filter(
    (username) => username !== localStorage.getItem("username")
  );

  // Require at least 2 other members (3 total including creator)
  if (!groupName) {
    alert("Please enter a group name.");
    return;
  }
  if (selectedMembers.length < 2) {
    alert("Please add at least two other members (minimum 3 total).");
    return;
  }

  console.log("Selected members:", selectedMembers); // Debug log

  try {
    const sessionId = sessionStorage.getItem("userSessionId"); // Retrieve the session ID
    if (!sessionId) {
      console.error("Session ID is missing. Redirecting to login page.");
      window.location.href = "index.html"; // Redirect to login if session ID is missing
      return;
    }

    const response = await fetch("/createGroupChat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Session-Id": sessionId,
      },
      body: JSON.stringify({
        name: groupName,
        members: selectedMembers,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      alert("Group created successfully!");

      // Add the new group to the sidebar
      const groupItem = document.createElement("li");
      groupItem.textContent = groupName;
      groupItem.dataset.groupId = data.groupId;
      groupItem.classList.add("group-item");
      groupItem.addEventListener("click", () => {
        selectChat(data.groupId, true);
      });
      document.getElementById("chat-list").appendChild(groupItem);

      // Close the modal
      createGroupModal.style.display = "none";
    } else {
      alert("Failed to create group.");
    }
  } catch (error) {
    console.error("Error creating group:", error);
    alert("An error occurred while creating the group.");
  }
});

// Handle Enter key press to send a message
messageInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault(); // Prevent default behavior (e.g., adding a new line)
    document.getElementById("send-button").click(); // Trigger the send button click
  }
});

// Zoom-in functionality for images
const imageZoomModal = document.getElementById("image-zoom-modal");
const zoomedImage = document.getElementById("zoomed-image");
const closeImageZoom = document.getElementById("close-image-zoom");

document.addEventListener("click", (event) => {
  if (event.target.tagName === "IMG" && event.target.closest(".message")) {
    // Open the modal and display the clicked image
    zoomedImage.src = event.target.src;
    imageZoomModal.style.display = "block";
  }
});

closeImageZoom.addEventListener("click", () => {
  imageZoomModal.style.display = "none";
});

window.addEventListener("click", (event) => {
  if (event.target === imageZoomModal) {
    imageZoomModal.style.display = "none";
  }
});

// Functionality for switching between profile and password tabs
const profileTabBtn = document.getElementById("profile-tab-btn");
const passwordTabBtn = document.getElementById("password-tab-btn");
const profileTab = document.getElementById("profile-tab");
const passwordTab = document.getElementById("password-tab");

profileTabBtn.addEventListener("click", () => {
  profileTabBtn.classList.add("active");
  passwordTabBtn.classList.remove("active");
  profileTab.classList.add("active");
  passwordTab.classList.remove("active");
});

passwordTabBtn.addEventListener("click", () => {
  passwordTabBtn.classList.add("active");
  profileTabBtn.classList.remove("active");
  passwordTab.classList.add("active");
  profileTab.classList.remove("active");
});

const profilePasswordInput = document.getElementById("edit-password");
const profileStrengthBar = document.getElementById(
  "profile-password-strength-bar"
);
const profileReqLength = document.getElementById("profile-req-length");
const profileReqUpper = document.getElementById("profile-req-upper");
const profileReqLower = document.getElementById("profile-req-lower");
const profileReqDigit = document.getElementById("profile-req-digit");
const profileReqSpecial = document.getElementById("profile-req-special");

if (profilePasswordInput) {
  profilePasswordInput.addEventListener("input", function () {
    const value = profilePasswordInput.value;
    let strength = 0;

    // Check requirements
    const lengthOK = value.length >= 8;
    const upperOK = /[A-Z]/.test(value);
    const lowerOK = /[a-z]/.test(value);
    const digitOK = /\d/.test(value);
    const specialOK = /[^A-Za-z0-9]/.test(value);

    // Update requirements list
    profileReqLength.style.color = lengthOK ? "green" : "red";
    profileReqUpper.style.color = upperOK ? "green" : "red";
    profileReqLower.style.color = lowerOK ? "green" : "red";
    profileReqDigit.style.color = digitOK ? "green" : "red";
    profileReqSpecial.style.color = specialOK ? "green" : "red";

    // Calculate strength
    strength += lengthOK ? 1 : 0;
    strength += upperOK ? 1 : 0;
    strength += lowerOK ? 1 : 0;
    strength += digitOK ? 1 : 0;
    strength += specialOK ? 1 : 0;

    // Update strength bar
    const colors = ["#e53935", "#ff9800", "#fbc02d", "#43a047", "#388e3c"];
    profileStrengthBar.style.width = strength * 20 + "%";
    profileStrengthBar.style.background = colors[strength - 1] || "#e53935";
  });
}

// Function to render group members
async function renderGroupMembers() {
  if (!currentGroupId) return;
  const response = await fetch(`/getGroupInfo?groupId=${currentGroupId}`);
  if (response.ok) {
    const data = await response.json();
    groupMembersList.innerHTML = "";
    data.members.forEach((member) => {
      const li = document.createElement("li");
      li.textContent = member.username;
      if (
        isGroupOwner &&
        member.username !== localStorage.getItem("username")
      ) {
        const removeBtn = document.createElement("button");
        removeBtn.textContent = "Remove";
        removeBtn.className = "remove-member-btn";
        removeBtn.onclick = async () => {
          await fetch("/removeGroupMember", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Session-Id": sessionStorage.getItem("userSessionId"),
            },
            body: JSON.stringify({
              groupId: currentGroupId,
              username: member.username,
            }),
          });
          renderGroupMembers(); // Refresh after removal
        };
        li.appendChild(removeBtn);
      }
      groupMembersList.appendChild(li);
    });
    groupOwnerActions.style.display = isGroupOwner ? "block" : "none";
  }
}

// Function to insert a date divider in the chatbox
function insertDateDivider(dateObj, prepend = false) {
  const divider = document.createElement("div");
  divider.className = "date-divider";
  divider.textContent = dateObj
    .toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    })
    .replace(",", " -");
  if (prepend) {
    chatBox.insertBefore(divider, chatBox.firstChild);
  } else {
    chatBox.appendChild(divider);
  }
}
