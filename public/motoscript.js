class Post {
    constructor(content, tags) {
        this.content = content;
        this.tags = tags;
        this.timestamp = new Date();
        this.comments = [];
        this.id = Date.now();
    }
}

let posts = [];
let locations = [];
let reviews = [];
let news = [];
let repairShops = [];
let tips = [];

function createPost() {
    const content = document.getElementById('postContent').value;
    const tagsInput = document.getElementById('tagsInput').value;
    if (!content) return;

    const tags = tagsInput.match(/@[\w]+/g) || [];
    const post = new Post(content, tags);
    posts.unshift(post);
    
    document.getElementById('postContent').value = '';
    document.getElementById('tagsInput').value = '';
    renderFeed();
}

function addComment(postId) {
    const commentInput = document.getElementById(`comment-${postId}`);
    const commentText = commentInput.value.trim();
    if (!commentText) return;

    const post = posts.find(p => p.id === postId);
    if (post) {
        post.comments.push(commentText);
        commentInput.value = '';
        renderFeed();
    }
}

function renderFeed() {
    const feed = document.getElementById('feed');
    feed.innerHTML = '';

    posts.forEach(post => {
        const postElement = document.createElement('div');
        postElement.className = 'post';
        
        const tagsHtml = post.tags.length ? 
            `<div class="tags">${post.tags.join(' ')}</div>` : '';
        
        const commentsHtml = post.comments.map(comment => 
            `<div class="comment">${comment}</div>`
        ).join('');

        postElement.innerHTML = `
            <div class="post-header">
                <div class="avatar"></div>
                <div>
                    <span class="username">Rider_${Math.floor(Math.random() * 1000)}</span>
                    <span class="timestamp">${formatTime(post.timestamp)}</span>
                </div>
            </div>
            <div class="content">${post.content}</div>
            ${tagsHtml}
            <div class="comments">
                ${commentsHtml}
                <input class="comment-input" id="comment-${post.id}" 
                       placeholder="Add a comment..." 
                       onkeypress="if(event.key === 'Enter') addComment(${post.id})">
            </div>
        `;
        
        feed.appendChild(postElement);
    });
}

function renderSection(sectionId, items) {
    const content = document.getElementById(`${sectionId}-content`);
    content.innerHTML = items.map(item => 
        `<div class="section-item">${item}</div>`
    ).join('');
}

function addLocation() {
    const location = prompt("Enter a riding spot:");
    if (location) {
        locations.push(location);
        renderSection('location', locations);
    }
}

function addReview() {
    const review = prompt("Enter your gear review:");
    if (review) {
        reviews.push(review);
        renderSection('reviews', reviews);
    }
}

function addRepairShop() {
    const shop = prompt("Enter repair shop name and location:");
    if (shop) {
        repairShops.push(shop);
        renderSection('repairshops', repairShops);
    }
}

function addTip() {
    const tip = prompt("Enter your riding tip:");
    if (tip) {
        tips.push(tip);
        renderSection('tips', tips);
    }
}

function formatTime(date) {
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
}

// Initial data
posts.push(new Post("Just finished a great ride on my Harley! #MotorcycleLife", ["@roadking", "@bikerbro"]));
posts.push(new Post("Anyone up for a group ride this weekend?", ["@rideordie"]));
locations.push("Twisties at Dragon's Tail");
reviews.push("5/5 stars for RevZilla helmet - great protection!");
news.push("New Harley model announced for 2025");
repairShops.push("Mike's Bike Shop - Denver, CO");
tips.push("Check tire pressure before every ride");

// Initial render
renderFeed();
renderSection('location', locations);
renderSection('reviews', reviews);
renderSection('news', news);
renderSection('repairshops', repairShops);
renderSection('tips', tips);
