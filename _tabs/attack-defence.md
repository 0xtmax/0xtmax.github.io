---
title: Attack & Defence
icon: fas fa-lock
order: 2
---

<link rel="stylesheet" href="/assets/css/attack-defence-course.css">
<link rel="stylesheet" href="/assets/css/tools-dashboard.css">
<script src="/assets/js/attack-defence-dashboard.js" defer></script>

<div id="tools-list" class="tools-list1">
  <!-- Course cards will be dynamically populated -->
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
  // Wait for the dashboard script to load
  function addOSEnumCard() {
    var toolsContainer = document.getElementById('tools-list');
    if (!toolsContainer) return;
    var osCard = document.createElement('div');
    osCard.classList.add('ad-course-card');
    osCard.innerHTML = `
      <h2>Operating System Enumeration</h2>
      <div class="card-date">${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}-${String(new Date().getDate()).padStart(2, '0')}</div>
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
      <button class="view-course-btn">View</button>
    `;
    osCard.querySelector('.view-course-btn').addEventListener('click', function() {
      alert('Operating System Enumeration content coming soon!');
    });
    toolsContainer.appendChild(osCard);
  }
  // Wait for the dashboard script to finish rendering the first card
  setTimeout(addOSEnumCard, 500);
});
</script>

