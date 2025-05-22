document.addEventListener('DOMContentLoaded', function() {
  // DOM elements
  const searchInput = document.getElementById('tools-search');
  const categoryTabs = document.getElementById('tools-nav');
  const toolsList = document.getElementById('tools-list');
  const toolDetails = document.getElementById('tool-details');
  
  // Initialize the dashboard
  function initDashboard() {
    // Get tools data from the external database
    const toolsData = window.toolsDatabase.tools;
    const categories = window.toolsDatabase.categories;
    
    renderCategories(categories);
    renderToolsList(toolsData);
    
    if (toolsData.length > 0) {
      showToolDetails(toolsData[0].id);
      
      // Set the first tool as active
      const firstToolItem = document.querySelector('.tool-item');
      if (firstToolItem) {
        firstToolItem.classList.add('active');
      }
    }
    
    // Add event listeners
    searchInput.addEventListener('input', function() {
      handleSearch(toolsData);
    });
  }
  
  // Render category tabs
  function renderCategories(categories) {
    // Create category tabs HTML
    const tabsHTML = ['All Tools', ...categories].map((category, index) => {
      return `<button class="category-tab ${index === 0 ? 'active' : ''}" data-category="${category}">${category}</button>`;
    }).join('');
    
    // Set the HTML
    categoryTabs.innerHTML = tabsHTML;
    
    // Add event listeners to tabs
    categoryTabs.querySelectorAll('.category-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        // Get tools data
        const toolsData = window.toolsDatabase.tools;
        
        // Set active tab
        categoryTabs.querySelectorAll('.category-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Filter tools by category
        const category = tab.dataset.category;
        if (category === 'All Tools') {
          renderToolsList(toolsData);
        } else {
          const filteredTools = toolsData.filter(tool => tool.category === category);
          renderToolsList(filteredTools);
        }
      });
    });
  }
  
  // Render tools list
  function renderToolsList(tools) {
    // Create tools list HTML
    const toolsHTML = tools.map(tool => {
      return `
        <div class="tool-item" data-tool-id="${tool.id}">
          <h3>${tool.name}</h3>
          <p>${tool.description}</p>
          <span class="tool-category-tag">${tool.category}</span>
        </div>
      `;
    }).join('');
    
    // Set the HTML
    toolsList.innerHTML = toolsHTML || '<div class="no-tools">No tools found</div>';
    
    // Add event listeners to tool items
    toolsList.querySelectorAll('.tool-item').forEach(item => {
      item.addEventListener('click', () => {
        // Set active tool
        toolsList.querySelectorAll('.tool-item').forEach(t => t.classList.remove('active'));
        item.classList.add('active');
        
        // Show tool details
        const toolId = item.dataset.toolId;
        showToolDetails(toolId);
      });
    });
  }
  
  // Show tool details
  function showToolDetails(toolId) {
    // Get tools data
    const toolsData = window.toolsDatabase.tools;
    
    // Find the tool
    const tool = toolsData.find(t => t.id === toolId);
    if (!tool) return;
    
    // Create commands HTML if available
    let commandsHTML = '';
    if (tool.commands && tool.commands.length > 0) {
      commandsHTML = `
        <div class="tool-commands">
          <h3>Basic Commands</h3>
          <div class="commands-list">
            ${tool.commands.map(cmd => `
              <div class="command-item">
                <div class="command-code">
                  <code>${cmd.cmd}</code>
                  <button class="copy-button" onclick="copyToClipboard('${cmd.cmd.replace(/'/g, "\\'")}')">Copy</button>
                </div>
                <p class="command-desc">${cmd.desc}</p>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }
    
    // Create details HTML
    const detailsHTML = `
      <div class="tool-header">
        <h2>${tool.name}</h2>
        <span class="tool-category">${tool.category}</span>
      </div>
      
      <div class="tool-description">
        <p>${tool.description}</p>
      </div>
      
      ${commandsHTML}
      
      <div class="tool-links">
        <a href="${tool.docs}" target="_blank" rel="noopener noreferrer">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
            <polyline points="15 3 21 3 21 9"></polyline>
            <line x1="10" y1="14" x2="21" y2="3"></line>
          </svg>
          Documentation / Cheatsheet
        </a>
      </div>
    `;
    
    // Set the HTML
    toolDetails.innerHTML = detailsHTML;
  }
  
  // Handle search
  function handleSearch(toolsData) {
    const searchTerm = searchInput.value.toLowerCase();
    if (!searchTerm) {
      renderToolsList(toolsData);
      return;
    }
    
    const filteredTools = toolsData.filter(tool => {
      return (
        tool.name.toLowerCase().includes(searchTerm) ||
        tool.description.toLowerCase().includes(searchTerm) ||
        tool.category.toLowerCase().includes(searchTerm)
      );
    });
    
    renderToolsList(filteredTools);
  }
  
  // Initialize the dashboard
  initDashboard();
});
