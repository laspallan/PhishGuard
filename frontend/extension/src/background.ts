/// <reference types="chrome" />

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    fetch("http://localhost:8000/scan/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.verdict === "block") {
          chrome.tabs.update(tabId, { url: "chrome://newtab" });
        }
      })
      .catch(() => {});
  }
});
