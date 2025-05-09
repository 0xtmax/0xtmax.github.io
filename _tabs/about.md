---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

>  
This page is intended for educational and ethical purposes only. All information, tools, and techniques shared are meant to promote awareness, enhance cybersecurity defenses, and foster responsible practices. Unauthorized access to systems or data is illegal and unethical. Always seek proper permission before conducting any security-related activities. Use this knowledge responsibly.
{: .prompt-danger }

Check out my Youtube channel : [Zerotmax Youtube Channel](https://www.youtube.com/@0xtmax/featured)

<pre> &lt;div id="youtube-video"&gt;&lt;/div&gt; &lt;script&gt; const channelId = 'UCrWnGq_UuMYA7toLILNlh6w'; // Replace with your real channel ID const url = `https://www.youtube.com/feeds/videos.xml?channel_id=${channelId}`; fetch(`https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(url)}`) .then(res =&gt; res.json()) .then(data =&gt; { const videoId = data.items[0].link.split('=')[1]; const iframe = ` &lt;iframe width="560" height="315" src="https://www.youtube.com/embed/${videoId}?autoplay=1&mute=1" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen&gt; &lt;/iframe&gt;`; document.getElementById('youtube-video').innerHTML = iframe; }); &lt;/script&gt; </pre>
