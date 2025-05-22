document.addEventListener('DOMContentLoaded', function() {
    const toolsContainer = document.getElementById('tools-list');
    const toolDetailsModal = document.createElement('div');
    toolDetailsModal.id = 'tool-details-modal';
    toolDetailsModal.classList.add('tool-details-modal');
    document.body.appendChild(toolDetailsModal);

    function renderCourseCard() {
    fetch('/assets/attack-defence-course.md')
        .then(response => response.text())
        .then(mdContent => {
            // Extract title from first '# ...' line
            const titleMatch = mdContent.match(/^#\s+(.+)$/m);
            const title = titleMatch ? titleMatch[1] : 'Active Directory Attacks: Complete Course Guide';
            // Extract first non-empty paragraph after the title
            const descMatch = mdContent.match(/\n\n([\s\S]*?)(\n\n|$)/);
            let description = descMatch ? descMatch[1].replace(/\*\*.*\*\*/g, '').replace(/\*/g, '').replace(/\_/g, '').trim() : '';
            if (!description || description.startsWith('#')) description = 'A comprehensive, step-by-step guide to Active Directory attacks.';

            const currentDate = new Date();
            const formattedDate = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}-${String(currentDate.getDate()).padStart(2, '0')}`;

            const courseCard = document.createElement('div');
            courseCard.classList.add('ad-course-card');
            courseCard.innerHTML = `
                <h2>${title}</h2>
                <div class="card-date">${formattedDate}</div>
                <p>A comprehensive, step-by-step guide to Active Directory attacks—from beginner concepts to advanced exploitation—equipping you with practical skills, tools, and techniques essential for real-world penetration testing, red teaming, and security analysis.</p>
                <div class="card-tags">
                    <span class="card-tag">Windows</span>
                    <span class="card-tag">Active Directory</span>
                    <span class="card-tag">Kerberos</span>
                </div>
                <div class="card-metrics">
                    <div class="metric">
                        <i class="fas fa-sitemap"></i>
                        <span>13 modules</span>
                    </div>
                </div>
                <div class="ad-course-btns">
                    <button class="view-course-btn">View</button>
                </div>
                
            `;

            courseCard.querySelector('.view-course-btn').addEventListener('click', showFullCourseView);
            toolsContainer.appendChild(courseCard);
        });
}

    function showFullCourseView() {
    // Fetch the markdown file
    fetch('/assets/attack-defence-course.md')
        .then(response => response.text())
        .then(mdContent => {
            // Ensure marked.js is loaded
            function renderModal(htmlContent) {
                toolDetailsModal.innerHTML = `
                    <div class="tool-details-modal-content">
                        <div class="tool-details-header">
                            
                            <button class="close-modal-btn">&times;</button>
                        </div>
                        <div class="tool-full-content">
                            <div class="markdown-content">${htmlContent}</div>
                        </div>
                    </div>
                `;

                toolDetailsModal.classList.add('show');

                const closeBtn = toolDetailsModal.querySelector('.close-modal-btn');
                closeBtn.addEventListener('click', () => {
                    toolDetailsModal.classList.remove('show');
                });

                toolDetailsModal.addEventListener('click', (e) => {
                    if (e.target === toolDetailsModal) {
                        toolDetailsModal.classList.remove('show');
                    }
                });
            }

            if (typeof window.marked === 'undefined') {
                // Load marked.js from CDN
                const script = document.createElement('script');
                script.src = 'https://cdn.jsdelivr.net/npm/marked/marked.min.js';
                script.onload = () => {
                    const htmlContent = window.marked.parse(mdContent);
                    renderModal(htmlContent);
                };
                document.head.appendChild(script);
            } else {
                const htmlContent = window.marked.parse(mdContent);
                renderModal(htmlContent);
            }
        });
}

    renderCourseCard();

    // Add Operating System Enumeration card
    function renderOSEnumCard() {
        const formattedDate = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}-${String(new Date().getDate()).padStart(2, '0')}`;
        const osCard = document.createElement('div');
        osCard.classList.add('ad-course-card');
        osCard.innerHTML = `
            <h2>Operating System Enumeration</h2>
            <div class="card-date">${formattedDate}</div>
            <p>Learn how to enumerate and analyze Windows and Linux operating systems for security weaknesses, user accounts, services, and misconfigurations as part of your attack and defence workflow.</p>
            <div class="card-tags">
                <span class="card-tag">Windows</span>
                <span class="card-tag">Linux</span>
                <span class="card-tag">Enumeration</span>
            </div>
            <div class="card-metrics">
                <div class="metric">
                    <i class="fas fa-desktop"></i>
                    <span>OS Enumeration</span>
                </div>
            </div>
            <div class="ad-course-btns">
                <button class="view-course-btn">View</button>
            </div>
        `;
        osCard.querySelector('.view-course-btn').addEventListener('click', function() {
            alert('Operating System Enumeration content coming soon!');
        });
        toolsContainer.appendChild(osCard);
    }
    renderOSEnumCard();
});
