# NCT - YouTube Streaming from JSON

This project loads video metadata (title, description, link) from `videos.json` and shows a YouTube embed player in `index.php`.

Run locally:

```bash
php -S 0.0.0.0:8000
# then open http://localhost:8000/index.php
```

Troubleshooting embed errors
----------------------------

- If a video doesn't play, open the browser devtools (F12) and check the Console/Network tab for errors.
- Try opening the raw embed URL in a new tab: `https://www.youtube.com/embed/VIDEOID` (replace VIDEOID). If that fails, the problem is with the video or YouTube settings (not your code).
- Common causes of blocked playback:
  - Owner disabled embedding on external sites (YouTube error 101/150 behavior).
  - Geographic or age restrictions (video must be played on youtube.com with login).
  - The video is private or removed.
  - Domain mismatch or missing origin — we now add an `origin` parameter to the embed URL to address this.

What to try if you see an error code (e.g., 157)
1. Open the embed URL in a new tab — does it load? If not, the video is restricted.
2. Check the console/network for a 4xx/403 response; check the `x-` headers and any JSON error message returned by the YT domain.
3. For privacy or owner restrictions, only the video owner can allow embedding.
4. For local testing, run using `php -S 0.0.0.0:8000` then use `http://localhost:8000/index.php`; test embed in that environment.
