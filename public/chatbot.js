function sendMessage(inputValue) {
    const chatInput = inputValue || document.getElementById("chatInput").value.toLowerCase();
    const chatbox = document.getElementById("chatbox");
    const loading = document.getElementById("loading");

    if (!inputValue) {
        chatbox.innerHTML += `<div class="message user"><p>You: ${chatInput}</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
        document.getElementById("chatInput").value = "";
    }

    if (chatInput === "report") {
        loading.style.display = "block";
        fetch('http://localhost:8000/report', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        })
        .then(response => {
            console.log("Response status (report):", response.status);
            if (response.status === 401 || response.redirected) {
                console.log('Unauthorized or redirected to login. Redirecting to login page...');
                window.location.href = "/login";
                return;
            }
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.message + (errorData.details ? `: ${errorData.details}` : ''));
                });
            }
            return response.json();
        })
        .then(data => {
            loading.style.display = "none";
            console.log("Response data (report):", data);
            const attacks = data.attacks;
            if (attacks && attacks.length > 0) {
                attacks.forEach(a => {
                    chatbox.innerHTML += `<div class="message bot"><p>Attack: ${a.type} from ${a.ip} at ${a.time} - ${a.details || 'No details'}</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
                });
            } else {
                chatbox.innerHTML += `<div class="message bot"><p>No attacks detected.</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
            }
            chatbox.scrollTop = chatbox.scrollHeight;
        })
        .catch(error => {
            loading.style.display = "none";
            console.error('Error fetching report:', error);
            chatbox.innerHTML += `<div class="message bot"><p>Error fetching report: ${error.message}</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
            chatbox.scrollTop = chatbox.scrollHeight;
        });
    } else if (chatInput === "exit") {
        chatbox.innerHTML += `<div class="message bot"><p>Goodbye.</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
        chatbox.scrollTop = chatbox.scrollHeight;
    } else if (chatInput === "blocked") {
        fetchBlockedIPs();
    } else {
        chatbox.innerHTML += `<div class="message bot"><p>Type 'report', 'exit', or 'blocked'.</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
        chatbox.scrollTop = chatbox.scrollHeight;
    }
}

function fetchBlockedIPs() {
    const blockedIpsDiv = document.getElementById("blocked-ips-list");
    const loading = document.getElementById("loading");
    loading.style.display = "block";

    console.log("Fetching blocked IPs..."); // Debug log

    fetch('http://localhost:8000/blocked-ips', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include'
    })
    .then(response => {
        console.log("Response status (blocked-ips):", response.status); // Debug log
        if (response.status === 401 || response.redirected) {
            console.log('Unauthorized or redirected to login. Redirecting to login page...');
            window.location.href = "/login";
            return;
        }
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        loading.style.display = "none";
        console.log("Blocked IPs data:", data); // Debug log
        if (data.status === "success" && data.blocked_ips && data.blocked_ips.length > 0) {
            blockedIpsDiv.innerHTML = data.blocked_ips.map(ip => `
                <div class="blocked-ip">
                    <span>${ip.ip} (${ip.reason}, Expires: ${new Date(ip.expires * 1000).toLocaleString()})</span>
                    <button onclick="unblockIP('${ip.ip}')">Unblock</button>
                </div>
            `).join('');
        } else {
            blockedIpsDiv.innerHTML = '<p>No blocked IPs.</p>';
        }
    })
    .catch(error => {
        loading.style.display = "none";
        console.error('Error fetching blocked IPs:', error);
        blockedIpsDiv.innerHTML = `<p>Error fetching blocked IPs: ${error.message}</p>`;
    });
}

function unblockIP(ip) {
    const loading = document.getElementById("loading");
    loading.style.display = "block";

    console.log(`Unblocking IP: ${ip}`); // Debug log

    fetch('http://localhost:8000/unblock-ip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: ip }),
        credentials: 'include'
    })
    .then(response => {
        console.log("Response status (unblock-ip):", response.status); // Debug log
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        loading.style.display = "none";
        console.log("Unblock response:", data); // Debug log
        if (data.status === "success") {
            fetchBlockedIPs(); // Refresh the list
        } else {
            alert(`Error unblocking IP: ${data.message}`);
        }
    })
    .catch(error => {
        loading.style.display = "none";
        console.error('Error unblocking IP:', error);
        alert(`Error unblocking IP: ${error.message}`);
    });
}

function logout() {
    fetch('http://localhost:8000/logout', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        window.location.href = "/login";
    })
    .catch(error => {
        console.error('Error during logout:', error);
        alert("Error during logout: " + error.message);
    });
}

// Uncomment to enable polling
// function pollReport() {
//     setInterval(() => {
//         sendMessage('report');
//     }, 5000);
// }
// window.onload = pollReport;