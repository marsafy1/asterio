chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fetchData') {
      const apiToken = 'YOUR_API_TOKEN';
      const url = request.url;
      const method = request.method;
      const body = request.body || null;

      let fetchOptions = {
        method: method,
        headers: {
          'Authorization': `Bearer ${apiToken}`, // Adjust the header name if necessary
          'Content-Type': 'application/json',
          'X-Apikey': apiToken
        }
      };

      if (method === 'POST' && body) {
        fetchOptions.body = `url=${body.url}`
      }

      fetch(url, fetchOptions)
      .then(response => response.json())
      .then(data => {
        sendResponse({ data });
      })
      .catch(error => {
        console.error('Error scanning URL with VirusTotal:', error);
        sendResponse({ error: error.message });
      });
  
      // Indicate that we'll send a response asynchronously
      return true;
    }
  });
  