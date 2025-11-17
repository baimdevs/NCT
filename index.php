<?php
// Function to extract YouTube video ID from various YouTube URLs
function getYoutubeId($url) {
    if (preg_match('#(?:youtu\.be/|youtube\.com(?:/embed/|/v/|/watch\?v=))([a-zA-Z0-9_-]{11})#', $url, $m)) {
        return $m[1];
    }
    return null;
}

// Load videos from JSON
$videosFile = __DIR__ . '/videos.json';
$videos = [];
$currentVideo = null;

if (file_exists($videosFile)) {
    $jsonContent = file_get_contents($videosFile);
    $data = json_decode($jsonContent, true);
    
    if (is_array($data)) {
        foreach ($data as $item) {
            $videoId = getYoutubeId($item['link']);
            if ($videoId) {
                $item['videoId'] = $videoId;
                // add sanitized origin to help YouTube confirm allowed embeds; PHP will set HOST if available
                $origin = isset($_SERVER['HTTP_HOST']) ? (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] : '';
                $params = [];
                if ($origin) {
                    $params[] = 'origin=' . urlencode($origin);
                }
                // we will add modest branding and disable related videos by default
                $params[] = 'rel=0';
                $params[] = 'modestbranding=1';
                $query = count($params) ? '?' . implode('&', $params) : '';
                $item['embedUrl'] = "https://www.youtube.com/embed/" . $videoId . $query;
                $videos[] = $item;
            }
        }
    }
}

// Set first video as current
if (!empty($videos)) {
    $currentVideo = $videos[0];
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Video Streaming - YouTube Playlist</title>
    <link rel="stylesheet" href="assets/styles.css">
</head>
<body>
    <div class="container">
        <aside class="sidebar">
            <h2>Daftar Video</h2>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Cari judul...">
            </div>
            <ul class="video-list" id="videoList">
                <?php foreach ($videos as $index => $video): ?>
                    <li class="video-item <?php echo $index === 0 ? 'active' : ''; ?>" data-index="<?php echo $index; ?>">
                        <div class="video-title"><?php echo htmlspecialchars($video['title'], ENT_QUOTES); ?></div>
                        <div class="video-meta"><?php echo htmlspecialchars($video['description'], ENT_QUOTES); ?></div>
                    </li>
                <?php endforeach; ?>
            </ul>
        </aside>

        <main class="player-section">
            <div class="player-wrapper">
                <iframe 
                    id="videoPlayer" 
                    width="100%" 
                    height="600" 
                    src="<?php echo $currentVideo ? htmlspecialchars($currentVideo['embedUrl'], ENT_QUOTES) : ''; ?>" 
                    frameborder="0" 
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
                    allowfullscreen>
                </iframe>
            </div>

            <div class="video-info">
                <h1 id="videoTitle"><?php echo $currentVideo ? htmlspecialchars($currentVideo['title'], ENT_QUOTES) : 'Pilih video'; ?></h1>
                <p id="videoDescription"><?php echo $currentVideo ? htmlspecialchars($currentVideo['description'], ENT_QUOTES) : ''; ?></p>
                <div class="video-link">
                    <a id="videoLink" href="<?php echo $currentVideo ? htmlspecialchars($currentVideo['link'], ENT_QUOTES) : '#'; ?>" target="_blank" class="btn-youtube">
                        Buka di YouTube
                    </a>
                </div>
            </div>
        </main>
    </div>

    <script>
        // Pass video data to JavaScript
        const videosData = <?php echo json_encode($videos); ?>;
    </script>
        <script src="assets/script.js"></script>
</body>
</html>
