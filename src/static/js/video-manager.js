class VideoManager {
    async deleteVideo(videoId) {
        if (!confirm('Are you sure you want to delete this video?')) return;
        
        try {
            const response = await fetch(`/api/videos/${videoId}`, {
                method: 'DELETE'
            });
            if (!response.ok) throw new Error('Failed to delete video');
            location.reload();
        } catch (err) {
            alert('Error deleting video');
        }
    }

    async editVideo(videoId) {
        const title = prompt('Enter new title:');
        const description = prompt('Enter new description:');
        
        if (!title) return;
        
        try {
            const response = await fetch(`/api/videos/${videoId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, description })
            });
            if (!response.ok) throw new Error('Failed to update video');
            location.reload();
        } catch (err) {
            alert('Error updating video');
        }
    }
}

class VideoPlayer {
    constructor(videoId) {
        this.player = null;
        this.videoId = videoId;
    }

    initPlayer() {
        // Initialize YouTube Player API
        this.player = new YT.Player('video-player', {
            videoId: this.videoId,
            events: {
                'onReady': this.onPlayerReady.bind(this)
            }
        });
    }

    jumpToTimestamp(timestamp) {
        if (!this.player) return;
        const seconds = this.convertTimestampToSeconds(timestamp);
        this.player.seekTo(seconds, true);
    }

    convertTimestampToSeconds(timestamp) {
        const parts = timestamp.split(':').reverse();
        return parts.reduce((acc, part, index) => {
            return acc + parseInt(part) * Math.pow(60, index);
        }, 0);
    }
}

// Make it globally available
window.videoManager = new VideoManager();
window.VideoPlayer = VideoPlayer;
