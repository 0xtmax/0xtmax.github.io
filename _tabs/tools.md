---
title: Tools
icon: fas fa-tools
order: 3
---

<link rel="stylesheet" href="/assets/css/tools-dashboard.css">
<script src="/assets/js/tools-data-complete.js" defer></script>
<script src="/assets/js/tools-dashboard.js" defer></script>

<div class="tools-container">
  <div class="tools-header">
    <h1>Security Tools Database</h1>
    <p>Search and explore penetration testing tools with documentation links</p>
    
    <div class="search-bar">
      <input type="text" id="tools-search" placeholder="Search tools...">
    </div>
  </div>
  
  <div class="tools-nav" id="tools-nav">
    <!-- Categories will be dynamically populated here -->
  </div>
  
  <div class="tools-content">
    <div class="tools-list" id="tools-list">
      <!-- Tools will be dynamically populated here -->
    </div>
    
    <div class="tool-details" id="tool-details">
      <!-- Tool details will be shown here -->
    </div>
  </div>
</div>
