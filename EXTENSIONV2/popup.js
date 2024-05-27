function takeScreenshot() {
    chrome.tabs.captureVisibleTab({ format: "png" }, function (screenshotUrl) {
        const link = document.createElement("a");
        link.href = screenshotUrl;
        link.download = "screenshot.png";
        link.click();
    });
}

// Attach the event listener to the button.
document.addEventListener("DOMContentLoaded", function () {
    const screenshotBtn = document.getElementById("screenshotBtn");

    if (screenshotBtn) {
        screenshotBtn.addEventListener("click", takeScreenshot);
    } else {
        console.error("Button not found.");
    }
});