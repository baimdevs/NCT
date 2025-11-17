document.addEventListener('DOMContentLoaded', function() {
    const videoList = document.getElementById('videoList');
    const videoPlayer = document.getElementById('videoPlayer');
    const videoTitle = document.getElementById('videoTitle');
    const videoDescription = document.getElementById('videoDescription');
    const videoLink = document.getElementById('videoLink');
    const searchInput = document.getElementById('searchInput');

    let filteredVideos = videosData;

    // Function to play a video
    function playVideo(video) {
        // append autoplay param when switching
        const origin = window.location.origin || (window.location.protocol + '//' + window.location.host);
        // Ensure embedUrl doesn't already have autoplay
        let src = video.embedUrl;
        const hasQuery = src.indexOf('?') >= 0;
        src += hasQuery ? '&autoplay=1' : '?autoplay=1';
        // If origin param is missing add it
        if (src.indexOf('origin=') === -1) {
            src += '&origin=' + encodeURIComponent(origin);
        }
        videoPlayer.src = src;
        videoTitle.textContent = video.title;
        videoDescription.textContent = video.description;
        videoLink.href = video.link;

        // Update active state
        document.querySelectorAll('.video-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-index="${videosData.indexOf(video)}"]`).classList.add('active');
    }

    // Function to render video list
    function renderVideoList(videos) {
        videoList.innerHTML = '';
        videos.forEach(video => {
            const li = document.createElement('li');
            li.className = 'video-item';
            if (video === videosData[0]) li.classList.add('active');
            li.dataset.index = videosData.indexOf(video);
            
            li.innerHTML = `
                <div class="video-title">${escapeHtml(video.title)}</div>
                <div class="video-meta">${escapeHtml(video.description)}</div>
            `;
            
            li.addEventListener('click', () => playVideo(video));
            videoList.appendChild(li);
        });
    }

    // Escape HTML function
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Search functionality
    searchInput.addEventListener('keyup', (e) => {
        const query = e.target.value.toLowerCase();
        filteredVideos = videosData.filter(video => 
            video.title.toLowerCase().includes(query) ||
            video.description.toLowerCase().includes(query)
        );
        renderVideoList(filteredVideos);

        if (filteredVideos.length > 0) {
            playVideo(filteredVideos[0]);
        }
    });

    // Initial render
    renderVideoList(videosData);
    if (videosData.length > 0) {
        playVideo(videosData[0]);
    }
});
