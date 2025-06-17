// Global variables
let currentUser = null;
let bugs = [];
let filteredBugs = [];
let currentPage = 1;
let bugsPerPage = 10;
let isLogin = true;

// API configuration
const API_URL = 'http://localhost:3000/api';  
// DOM elements
const authSection = document.getElementById('authSection');
const dashboardSection = document.getElementById('dashboardSection');
const authForm = document.getElementById('authForm');
const authTitle = document.getElementById('authTitle');
const authBtnText = document.getElementById('authBtnText');
const switchAuth = document.getElementById('switchAuth');
const userWelcome = document.getElementById('userWelcome');
const currentUserSpan = document.getElementById('currentUser');
const logoutBtn = document.getElementById('logoutBtn');
const bugModal = document.getElementById('bugModal');
const bugForm = document.getElementById('bugForm');
const bugList = document.getElementById('bugList');
const passwordConfirmGroup = document.getElementById('passwordConfirmGroup');
const loadMoreBtn = document.getElementById('loadMoreBtn');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadSampleData();
});

function initializeApp() {
    const token = getAuthToken();
    const savedUser = localStorage.getItem('currentUser');
    
    if (token && savedUser) {
        currentUser = JSON.parse(savedUser);
        showDashboard();
    } else {
        clearAuthToken(); // Clear any invalid tokens
        localStorage.removeItem('currentUser');
        showAuth();
    }
}

function setupEventListeners() {
    // Auth form
    authForm.addEventListener('submit', handleAuth);
    switchAuth.addEventListener('click', toggleAuthMode);
    logoutBtn.addEventListener('click', logout);

    // Bug modal and form
    document.getElementById('addBugBtn').addEventListener('click', () => openBugModal());
    document.getElementById('closeBugModal').addEventListener('click', closeBugModal);
    document.getElementById('cancelBugBtn').addEventListener('click', closeBugModal);
    bugForm.addEventListener('submit', handleBugSubmit);
    document.getElementById('generateTagsBtn').addEventListener('click', generateAITags);



    // Filters and search
    document.getElementById('statusFilter').addEventListener('change', applyFilters);
    document.getElementById('severityFilter').addEventListener('change', applyFilters);
    document.getElementById('sortBy').addEventListener('change', applyFilters);
    document.getElementById('searchInput').addEventListener('input', debounce(applyFilters, 300));

    // Tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Load more
    loadMoreBtn.addEventListener('click', loadMoreBugs);

    // Close modal on outside click
    bugModal.addEventListener('click', (e) => {
        if (e.target === bugModal) closeBugModal();
    });

    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

// Authentication functions
function setAuthToken(token) {
    localStorage.setItem('authToken', token);
}

function getAuthToken() {
    return localStorage.getItem('authToken');
}

function clearAuthToken() {
    localStorage.removeItem('authToken');
}

async function handleAuth(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const passwordConfirm = document.getElementById('passwordConfirm').value;

    if (!isLogin && password !== passwordConfirm) {
        showNotification('Passwords do not match!', 'error');
        return;
    }

    // Basic validation
    if (!username || !password) {
        showNotification('Username and password are required!', 'error');
        return;
    }

    // Add email validation for registration
    if (!isLogin && !isValidEmail(email)) {
        showNotification('Please enter a valid email address!', 'error');
        return;
    }

    showSpinner('authSpinner', 'authBtnText');

    try {
        const endpoint = isLogin ? '/auth/login' : '/auth/register';
        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email,
                password,
                full_name: username // You might want to add a full name field in your form
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Authentication failed');
        }

        if (data.token) {
            setAuthToken(data.token);
            currentUser = data.user;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            showNotification(isLogin ? 'Login successful!' : 'Registration successful!', 'success');
            showDashboard();
        } else {
            throw new Error('No token received');
        }
    } catch (error) {
        console.error('Auth error:', error);
        showNotification(error.message, 'error');
    } finally {
        hideSpinner('authSpinner', 'authBtnText', isLogin ? 'Login' : 'Register');
    }
}

function toggleAuthMode() {
    isLogin = !isLogin;
    if (isLogin) {
        authTitle.textContent = 'Login';
        authBtnText.textContent = 'Login';
        switchAuth.textContent = "Don't have an account? Register";
        passwordConfirmGroup.classList.add('hidden');
    } else {
        authTitle.textContent = 'Register';
        authBtnText.textContent = 'Register';
        switchAuth.textContent = 'Already have an account? Login';
        passwordConfirmGroup.classList.remove('hidden');
    }
}

function logout() {
    clearAuthToken();
    localStorage.removeItem('currentUser');
    currentUser = null;
    showAuth();
    showNotification('Logged out successfully!', 'info');
}

function showAuth() {
    authSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
    userWelcome.classList.add('hidden');
    logoutBtn.classList.add('hidden');
}

function showDashboard() {
    authSection.classList.add('hidden');
    dashboardSection.classList.remove('hidden');
    userWelcome.classList.remove('hidden');
    logoutBtn.classList.remove('hidden');
    currentUserSpan.textContent = currentUser.username;
    loadBugs();
    updateStats();
}

// Bug management functions
function loadSampleData() {
    const sampleBugs = [
        {
            id: 1,
            title: "Login button not responsive on mobile",
            description: "Users are unable to tap the login button in mobile view on iPhone 13. This only occurs in Safari browser.",
            severity: "Critical",
            status: "Open",
            assignedTo: "john_doe",
            createdAt: new Date('2024-01-15'),
            createdBy: "admin",
            steps: "1. Open Safari on iPhone 13\n2. Navigate to login page\n3. Try to tap login button\n4. Nothing happens",
            tags: ["UI", "Mobile", "Safari", "Critical"]
        },
        {
            id: 2,
            title: "Database connection timeout",
            description: "Application throws timeout error when connecting to database during peak hours.",
            severity: "High",
            status: "In Progress",
            assignedTo: "jane_smith",
            createdAt: new Date('2024-01-14'),
            createdBy: "admin",
            steps: "1. Deploy application\n2. Wait for peak traffic hours\n3. Monitor connection logs",
            tags: ["Database", "Performance", "Backend"]
        },
        {
            id: 3,
            title: "Email notifications not sending",
            description: "Users report they are not receiving email notifications for password resets and account updates.",
            severity: "Medium",
            status: "Resolved",
            assignedTo: "mike_jones",
            createdAt: new Date('2024-01-13'),
            createdBy: "support",
            steps: "1. Request password reset\n2. Check email inbox\n3. Wait 10 minutes\n4. Still no email received",
            tags: ["Email", "Notifications", "SMTP"]
        },
        {
            id: 4,
            title: "Page loading slowly",
            description: "The dashboard page takes more than 10 seconds to load completely with all widgets.",
            severity: "Low",
            status: "Closed",
            assignedTo: "sarah_wilson",
            createdAt: new Date('2024-01-12'),
            createdBy: "tester",
            steps: "1. Login to application\n2. Navigate to dashboard\n3. Time the loading process",
            tags: ["Performance", "UI", "Dashboard"]
        },
        {
            id: 5,
            title: "Form validation errors",
            description: "Contact form allows submission without required fields being filled.",
            severity: "High",
            status: "Open",
            assignedTo: "alex_brown",
            createdAt: new Date('2024-01-11'),
            createdBy: "qa_team",
            steps: "1. Go to contact page\n2. Leave required fields empty\n3. Click submit\n4. Form submits without validation",
            tags: ["Forms", "Validation", "Frontend"]
        }
    ];

    if (!localStorage.getItem('bugs')) {
        localStorage.setItem('bugs', JSON.stringify(sampleBugs));
    }
}

function loadBugs() {
    const savedBugs = localStorage.getItem('bugs');
    bugs = savedBugs ? JSON.parse(savedBugs) : [];
    // Convert date strings back to Date objects
    bugs.forEach(bug => {
        bug.createdAt = new Date(bug.createdAt);
    });
    applyFilters();
}

function saveBugs() {
    localStorage.setItem('bugs', JSON.stringify(bugs));
}

function applyFilters() {
    const statusFilter = document.getElementById('statusFilter').value;
    const severityFilter = document.getElementById('severityFilter').value;
    const sortBy = document.getElementById('sortBy').value;
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();

    filteredBugs = bugs.filter(bug => {
        const matchesStatus = !statusFilter || bug.status === statusFilter;
        const matchesSeverity = !severityFilter || bug.severity === severityFilter;
        const matchesSearch = !searchTerm || 
            bug.title.toLowerCase().includes(searchTerm) ||
            bug.description.toLowerCase().includes(searchTerm) ||
            bug.tags.some(tag => tag.toLowerCase().includes(searchTerm));

        return matchesStatus && matchesSeverity && matchesSearch;
    });

    // Sort bugs
    filteredBugs.sort((a, b) => {
        switch (sortBy) {
            case 'severity':
                const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
                return severityOrder[b.severity] - severityOrder[a.severity];
            case 'status':
                return a.status.localeCompare(b.status);
            case 'title':
                return a.title.localeCompare(b.title);
            case 'created_at':
            default:
                return new Date(b.createdAt) - new Date(a.createdAt);
        }
    });

    currentPage = 1;
    renderBugs();
    updateStats();
}

function renderBugs() {
    const startIndex = 0;
    const endIndex = currentPage * bugsPerPage;
    const bugsToShow = filteredBugs.slice(startIndex, endIndex);

    bugList.innerHTML = '';

    if (bugsToShow.length === 0) {
        bugList.innerHTML = `
            <div class="text-center" style="padding: 3rem;">
                <h3>No bugs found</h3>
                <p>Try adjusting your filters or add a new bug report.</p>
            </div>
        `;
        loadMoreBtn.classList.add('hidden');
        return;
    }

    bugsToShow.forEach(bug => {
        const bugCard = createBugCard(bug);
        bugList.appendChild(bugCard);
    });

    // Show/hide load more button
    if (endIndex < filteredBugs.length) {
        loadMoreBtn.classList.remove('hidden');
    } else {
        loadMoreBtn.classList.add('hidden');
    }
}

function createBugCard(bug) {
    const card = document.createElement('div');
    card.className = 'bug-card fade-in';
    
    const statusClass = bug.status.toLowerCase().replace(' ', '');
    const severityClass = bug.severity.toLowerCase();
    
    card.innerHTML = `
        <div class="bug-header">
            <div>
                <h3 class="bug-title">${bug.title}</h3>
                <div class="bug-id">Bug #${bug.id}</div>
            </div>
            <div class="bug-actions">
                <button class="btn btn-small btn-secondary" onclick="editBug(${bug.id})">
                    ✏️ Edit
                </button>
                <button class="btn btn-small btn-danger" onclick="deleteBug(${bug.id})">
                    🗑️ Delete
                </button>
            </div>
        </div>
        <p class="bug-description">${bug.description}</p>
        <div class="bug-meta">
            <div class="bug-meta-item">
                <span>📅</span>
                <span>${formatDate(bug.createdAt)}</span>
            </div>
            <div class="bug-meta-item">
                <span>👤</span>
                <span>Created by: ${bug.createdBy}</span>
            </div>
            ${bug.assignedTo ? `
            <div class="bug-meta-item">
                <span>👨‍💻</span>
                <span>Assigned to: ${bug.assignedTo}</span>
            </div>
            ` : ''}
        </div>
        <div class="flex-between" style="margin-top: 1rem;">
            <div class="flex gap-1">
                <span class="badge badge-${statusClass}">${bug.status}</span>
                <span class="badge badge-${severityClass}">${bug.severity}</span>
            </div>
        </div>
        ${bug.tags && bug.tags.length > 0 ? `
        <div class="tag-chips">
            ${bug.tags.map(tag => `<span class="tag-chip" onclick="filterByTag('${tag}')">${tag}</span>`).join('')}
        </div>
        ` : ''}
    `;

    return card;
}

function loadMoreBugs() {
    currentPage++;
    renderBugs();
}

function switchTab(tabName) {
    // Update active tab
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update status filter
    const statusFilter = document.getElementById('statusFilter');
    switch (tabName) {
        case 'all':
            statusFilter.value = '';
            break;
        case 'open':
            statusFilter.value = 'Open';
            break;
        case 'progress':
            statusFilter.value = 'In Progress';
            break;
        case 'resolved':
            statusFilter.value = 'Resolved';
            break;
        case 'closed':
            statusFilter.value = 'Closed';
            break;
    }

    applyFilters();
}

function filterByTag(tag) {
    document.getElementById('searchInput').value = tag;
    applyFilters();
}

// Bug modal functions
function openBugModal(bug = null) {
    const modalTitle = document.getElementById('modalTitle');
    const saveBugText = document.getElementById('saveBugText');

    if (bug) {
        modalTitle.textContent = 'Edit Bug';
        saveBugText.textContent = 'Update Bug';
        populateBugForm(bug);
    } else {
        modalTitle.textContent = 'Add New Bug';
        saveBugText.textContent = 'Save Bug';
        bugForm.reset();
        document.getElementById('bugId').value = '';
        document.getElementById('generatedTags').innerHTML = '';
    }

    bugModal.classList.add('show');
}

function closeBugModal() {
    bugModal.classList.remove('show');
    bugForm.reset();
}

function populateBugForm(bug) {
    document.getElementById('bugId').value = bug.id;
    document.getElementById('bugTitle').value = bug.title;
    document.getElementById('bugDescription').value = bug.description;
    document.getElementById('bugSeverity').value = bug.severity;
    document.getElementById('bugStatus').value = bug.status;
    document.getElementById('bugAssignedTo').value = bug.assignedTo || '';
    document.getElementById('bugSteps').value = bug.steps || '';
    
    if (bug.tags) {
        const tagsHtml = bug.tags.map(tag => 
            `<span class="tag-chip">${tag}</span>`
        ).join('');
        document.getElementById('generatedTags').innerHTML = tagsHtml;
    }
}

function handleBugSubmit(e) {
    e.preventDefault();
    
    const bugId = document.getElementById('bugId').value;
    const title = document.getElementById('bugTitle').value;
    const description = document.getElementById('bugDescription').value;
    const severity = document.getElementById('bugSeverity').value;
    const status = document.getElementById('bugStatus').value;
    const assignedTo = document.getElementById('bugAssignedTo').value;
    const steps = document.getElementById('bugSteps').value;
    
    // Get tags from generated tags section
    const tagElements = document.querySelectorAll('#generatedTags .tag-chip');
    const tags = Array.from(tagElements).map(el => el.textContent);

    showSpinner('saveBugSpinner', 'saveBugText');

    setTimeout(() => {
        if (bugId) {
            // Update existing bug
            const bugIndex = bugs.findIndex(bug => bug.id == bugId);
            if (bugIndex !== -1) {
                bugs[bugIndex] = {
                    ...bugs[bugIndex],
                    title,
                    description,
                    severity,
                    status,
                    assignedTo,
                    steps,
                    tags
                };
                showNotification('Bug updated successfully!', 'success');
            }
        } else {
            // Create new bug
            const newBug = {
                id: Date.now(),
                title,
                description,
                severity,
                status,
                assignedTo,
                steps,
                tags,
                createdAt: new Date(),
                createdBy: currentUser.username
            };
            bugs.unshift(newBug);
            showNotification('Bug created successfully!', 'success');
            
            // Show notification for assigned user
            if (assignedTo && 'Notification' in window && Notification.permission === 'granted') {
                new Notification('New Bug Assigned', {
                    body: `A new ${severity.toLowerCase()} priority bug has been assigned to you: ${title}`,
                    icon: '🐛'
                });
            }
        }

        saveBugs();
        applyFilters();
        closeBugModal();
        hideSpinner('saveBugSpinner', 'saveBugText', 'Save Bug');
    }, 1000);
}

function editBug(id) {
    const bug = bugs.find(bug => bug.id === id);
    if (bug) {
        openBugModal(bug);
    }
}

function deleteBug(id) {
    if (confirm('Are you sure you want to delete this bug?')) {
        bugs = bugs.filter(bug => bug.id !== id);
        saveBugs();
        applyFilters();
        showNotification('Bug deleted successfully!', 'success');
    }
}

// AI Tag Generation (Mock Implementation)
async function generateAITags() {
    const title = document.getElementById('bugTitle').value;
    const description = document.getElementById('bugDescription').value;
    const steps = document.getElementById('bugSteps')?.value || "";

    if (!title || !description) {
        showNotification('Title and description are required.', 'warning');
        return;
    }

    try {
        const res = await fetch('http://localhost:3000/api/ai/tags', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ title, description, steps })
        });

        const data = await res.json();

        if (res.ok) {
            const tags = data.tags.map(tag => {
                if (typeof tag === 'string') return tag;
                if (tag.name) return tag.name;
                if (tag.tag) return tag.tag;
                return JSON.stringify(tag);
            });

            // Update tags visually and in the hidden field
            const tagsHtml = tags.map(tag => `<span class="tag-chip">${tag}</span>`).join('');
            document.getElementById('generatedTags').innerHTML = tagsHtml;
            document.getElementById('bugTags').value = tags.join(', ');

            showNotification('AI tags generated!', 'success');
        } else {
            throw new Error(data.error || 'AI tag generation failed');
        }
    } catch (err) {
        console.error(err);
        showNotification('Failed to generate tags', 'error');
    }
}



// Statistics functions
function updateStats() {
    const totalBugsCount = bugs.length;
    const openBugsCount = bugs.filter(bug => bug.status === 'Open').length;
    const resolvedBugsCount = bugs.filter(bug => bug.status === 'Resolved').length;
    const criticalBugsCount = bugs.filter(bug => bug.severity === 'Critical').length;

    document.getElementById('totalBugs').textContent = totalBugsCount;
    document.getElementById('openBugs').textContent = openBugsCount;
    document.getElementById('resolvedBugs').textContent = resolvedBugsCount;
    document.getElementById('criticalBugs').textContent = criticalBugsCount;
}

// Utility functions
function formatDate(date) {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function showSpinner(spinnerId, textId) {
    document.getElementById(spinnerId).classList.remove('hidden');
    document.getElementById(textId).classList.add('hidden');
}

function hideSpinner(spinnerId, textId, originalText) {
    document.getElementById(spinnerId).classList.add('hidden');
    document.getElementById(textId).classList.remove('hidden');
    document.getElementById(textId).textContent = originalText;
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 4000);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Background notification checks (runs every 30 seconds)
setInterval(() => {
    if (currentUser && 'Notification' in window && Notification.permission === 'granted') {
        const criticalBugs = bugs.filter(bug => 
            bug.severity === 'Critical' && 
            bug.status === 'Open' && 
            bug.assignedTo === currentUser.username
        );
        
        if (criticalBugs.length > 0) {
            new Notification('Critical Bugs Alert', {
                body: `You have ${criticalBugs.length} critical bug(s) that need attention!`,
                icon: '🚨'
            });
        }
    }
}, 30000);

// Add function to make authenticated API calls
async function fetchWithAuth(url, options = {}) {
    const token = getAuthToken();
    const headers = {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...options.headers
    };

    try {
        const response = await fetch(`${API_URL}${url}`, {
            ...options,
            headers
        });

        if (response.status === 401) {
            // Token expired or invalid
            clearAuthToken();
            localStorage.removeItem('currentUser');
            showAuth();
            throw new Error('Session expired. Please login again.');
        }

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'API request failed');
        }

        return data;
    } catch (error) {
        console.error('API error:', error);
        showNotification(error.message, 'error');
        throw error;
    }
}

// Add this utility function before handleAuth
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}