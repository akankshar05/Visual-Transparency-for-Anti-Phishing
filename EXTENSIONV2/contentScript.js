chrome.runtime.sendMessage({greeting:"hello"}, function(response) {
    console.log(response.farewell);
});

// Send message to background script to capture screenshot
chrome.runtime.sendMessage({ action: "captureScreenshot" }, function(response) {
    if (response.success) {
        console.log("Screenshot captured and uploaded successfully");
        // Resume rendering of HTML page
        // Add your code to resume rendering here
    } else {
        console.error("Failed to capture or upload screenshot");
    }
});

// function takeScreenshot() {
//     chrome.tabs.captureVisibleTab({ format: "png" }, function (screenshotUrl) {
//         const link = document.createElement("a");
//         link.href = screenshotUrl;
//         link.download = "screenshot.png";
//         link.click();
//     });
// }

// // Attach the event listener to the button.
// document.addEventListener("DOMContentLoaded", function () {
//     const screenshotBtn = document.getElementById("screenshotBtn");

//     if (screenshotBtn) {
//         screenshotBtn.addEventListener("click", takeScreenshot);
//     } else {
//         console.error("Button not found.");
//     }
// });