/**
 * YouTube Video Embed
 * Displays a specific YouTube video
 */

document.addEventListener('DOMContentLoaded', function() {
  const videoId = 'SPAeMlPFeVk'; // Your specific video ID
  const youtubeContainer = document.getElementById('latest-youtube-video');
  
  if (!youtubeContainer) return;
  
  // Create the HTML for the embedded YouTube player with a specific video
  const embedHtml = `
    <div class="latest-video-container">
      <h3>Featured YouTube Video</h3>
      <div class="video-wrapper">
        <iframe 
          width="560" 
          height="315" 
          src="https://www.youtube.com/embed/${videoId}" 
          title="YouTube Video" 
          frameborder="0" 
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
          allowfullscreen>
        </iframe>
      </div>
      <div class="video-info">
        <p>Subscribe to my <a href="https://www.youtube.com/@0xtmax" target="_blank">YouTube channel</a> for more videos!</p>
      </div>
    </div>
  `;
  
  // Update the container
  youtubeContainer.innerHTML = embedHtml;
});
