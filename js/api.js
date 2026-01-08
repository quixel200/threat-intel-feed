export class API {
    constructor() {
        this.corsProxy = 'https://api.allorigins.win/get?url='; // Alternative proxy if needed, or rss2json
        this.rss2jsonBase = 'https://api.rss2json.com/v1/api.json?rss_url=';
    }

    async getCVEs() {
        try {
            // Using api.codetabs.com proxy to bypass CORS
            const response = await fetch(`https://api.codetabs.com/v1/proxy?quest=https://cve.circl.lu/api/last`);
            if (!response.ok) throw new Error('Network response was not ok');
            const data = await response.json();
            // codetabs returns the data directly
            return data;
        } catch (error) {
            console.error("Error fetching CVEs:", error);
            return [];
        }
    }

    async getRSSFeed(url) {
        try {
            const response = await fetch(`${this.rss2jsonBase}${encodeURIComponent(url)}`);
            if (!response.ok) throw new Error('Network response was not ok');
            const data = await response.json();
            return data.items || [];
        } catch (error) {
            console.error(`Error fetching RSS ${url}:`, error);
            return [];
        }
    }

    async getHackerNewsSecurity() {
        try {
            const response = await fetch('https://hn.algolia.com/api/v1/search_by_date?query=security&tags=story&hitsPerPage=20');
            if (!response.ok) throw new Error('Network response was not ok');
            const data = await response.json();
            return data.hits || [];
        } catch (error) {
            console.error("Error fetching HN:", error);
            return [];
        }
    }

    async getThreatNews() {
        const feeds = [
            'https://feeds.feedburner.com/TheHackersNews',
            'https://www.bleepingcomputer.com/feed/'
        ];

        const promises = feeds.map(url => this.getRSSFeed(url));
        const results = await Promise.all(promises);
        return results.flat().sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));
    }

    async getMalwareBazaar() {
        // Replacing abuse.ch with SANS ISC and Malware Traffic Analysis due to lack of RSS/CORS support
        const feeds = [
            'https://isc.sans.edu/rssfeed.xml',
            'https://www.malware-traffic-analysis.net/blog-entries.rss'
        ];

        const promises = feeds.map(url => this.getRSSFeed(url));
        const results = await Promise.all(promises);
        // Sort/Flat
        return results.flat().sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));
    }
}
