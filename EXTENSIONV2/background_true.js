let headers; // Declare headers in a scope accessible to both the event listener and the fetch request

chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        if (details.type === "main_frame") {
            headers = details.responseHeaders;  
        }
        console.log(headers)
    },
    {urls: ["<all_urls>"]},
    ["responseHeaders"]
);

// chrome.webNavigation.onDOMContentLoaded.addListener(function(details) {
//     chrome.tabs.captureVisibleTab(null, { format: "png" }, function(dataUrl) {
//         if (chrome.runtime.lastError) {
//             console.error(chrome.runtime.lastError.message);
//             return;
//         }
    
//         // Send the screenshot to the server
//         fetch('http://localhost:8000/upload', {
//             method: 'POST',
//             body: dataUrl
//         })
//         .then(response => {
//             if (!response.ok) {
//                 throw new Error('Failed to upload screenshot');
//             }
//             // Parse response as text
//             return response.text();
//         })
//         .then(responseText => {
//             // Check if response indicates phishing
//             if (responseText.trim() === 'phishing') {
//                 console.log('The screenshot is phishing.');
//                 // Handle phishing scenario
//             } else {
//                 console.log('The screenshot is not phishing.');
//                 // Handle non-phishing scenario
//             }
//         })
//         .catch(error => {
//             console.error('Error uploading screenshot:', error);
//         });
//     });
    
// });


chrome.runtime.onMessage.addListener(
    function (request, sender, sendResponse) {
         console.log(sender.tab ?
         "from a content script:" + sender.tab.url :
         "from the extension");
         if (request.greeting == "hello")
         sendResponse({ farewell: "goodbye" });
    });

    //**************************************************************
// Here it checks for login/non-login page. Login page is further processed. non-login is rendered directly.


// Function to check if a string contains any login keyword
function containsLoginKeyword(text) {
    return loginKeywords.some(keyword => text.includes(keyword));
}

// Function to check if the page likely contains a login form
function isLoginPage2() {
    const loginKeywords = [
        'username', 'password', 'login', 'signin', 'sign-in', 'log in', 'log-in', 'authenticate', 'credentials', 
        'access', 'enter', 'account', 'identity', 'user', 'email', 'e-mail', 'passcode', 'customer number', 
        'pin', 'secret code', 'authentication code', 'security code', 'passphrase', 'account number', 
        'membership number', 'social security number', 'registration code', 'authorization code', 'login code', 
        'secure login', 'unique identifier', 'login id', 'login name', 'login details', 'login information', 
        'login credentials', 'login data', 'login token', 'login key'
    ];
    
    // entireDOM = document.documentElement.outerHTML.toLowerCase();
    // console.log("getit ram ram ");
    // console.log(entireDOM)
    // Check if there are form elements
    // console.log("hi***********************************");
    // console.log("");
    // console.log(document);
    // const filePath = 'output.txt';

// Write data to the file
    // fs.writeFile(filePath, document, (err) => {
    // if (err) {
    //     console.error('Error writing to file:', err);
    //     return;
    // }
    // console.log('Data has been written to', filePath);
    // });
    // console.log("hi***********************************");
    // console.log("");
    var forms = document.querySelectorAll('form');
    if (forms.length > 0) {
        // console.log(forms.length)
        // Loop through each form and check for input fields
        for (var i = 0; i < forms.length; i++) {
            var inputs = forms[i].querySelectorAll('input[type="text"], input[type="email"], input[type="password"]');
            // console.log(inputs);
            // console.log(inputs.length);

            if (inputs.length > 0) {
                // console.log("I am inside");

                // console.log("))))))))))))))))))");
                // Check for login keywords in form attributes, text nodes, alt, and title attributes
                var formText = forms[i].innerText.toLowerCase();
                var alttext = forms[i].getAttribute('alt');
                if (alttext)
                {
                    alttext = alttext.toLowerCase();
                    if(loginKeywords.some(keyword => alttext.includes(keyword)))
                    {
                        // console.log("happy");
                        return true;
                    }
                }
                var titletext = forms[i].getAttribute('title');
                if(titletext)
                {
                    titletext = titletext.toLowerCase();
                    if(loginKeywords.some(keyword => titletext.includes(keyword)))
                    {
                        // console.log("happy");
                        return true;
                    }
                }
                // console.log(formText);

                if(loginKeywords.some(keyword => formText.includes(keyword)))
                {
                    // console.log("happy");
                    return true;
                }

               

             
            }
        }

    }
    // var searchForms = document.querySelectorAll('form:not([action*="search"])'); // Exclude search forms
    // for (var j = 0; j < searchForms.length; j++) {
    //     if (searchLoginKeywordsUp(searchForms[j], 3)) {
    //         return true;
    //     }
    // }
    
    // // Check for phishing pattern with login keywords in images
    // var images = document.querySelectorAll('img');
    // var hasText = document.body.innerText.trim().length > 0;
    // if (!hasText && images.length > 0) {
    //     for (var k = 0; k < images.length; k++) {
    //         var
    //         if (containsLoginKeyword(images[k].getAttribute('alt').toLowerCase())) {
    //             return true;
    //         }
    //     }
    // }

    // Check if the URL contains keywords indicating a login, signup, or signin page

    var urlKeywords = ['login', 'signin', 'signup', 'sign-in', 'log-in', 'sign-up'];
    var currentPageUrl = window.location.href.toLowerCase();
    for (var j = 0; j < urlKeywords.length; j++) {
        if (currentPageUrl.includes(urlKeywords[j])) {
            // console.log("2");
            return true;
        }
    }
    
    // Check if page title contains keywords
    var pageTitleKeywords = ['login', 'signin', 'signup', 'sign-in', 'log-in', 'sign-up'];
    var pageTitle = document.title.toLowerCase();
    for (var k = 0; k < pageTitleKeywords.length; k++) {
        if (pageTitle.includes(pageTitleKeywords[k])) {
            // console.log("3")
            return true;
        }
    }
    
    // Check for login keywords in the entire DOM tree
    // var entireDOM = document.documentElement.outerHTML.toLowerCase();
    // console.log("getit....................")
    // console.log(entireDOM)
    // if (containsLoginKeyword(entireDOM)) {
    // if(loginKeywords.some(keyword => entireDOM.includes(keyword)))

        // return true;
    
    // No login form found
    return false;
}
///////////////////VERIFY((((((((()))))))))  



//*************************************************** */

// Event listener for webNavigation.onDOMContentLoaded
// chrome.webNavigation.onDOMContentLoaded.addListener(function(details) {
//     // Execute isLoginPage function when DOM content is loaded
//     var htmlContent;
//     chrome.tabs.executeScript(details.tabId, { code: 'document.documentElement.outerHTML' }, function(result) {
//         // Check if the result is an array with at least one element
//         if (Array.isArray(result) && result.length > 0) {
//             // Extract the HTML content from the first element of the result array
//             htmlContent = result[0];
            
//             // Process the HTML content here
//             console.log(htmlContent);
//         }
//     });


//     chrome.tabs.executeScript(details.tabId, { code: '(' + isLoginPage2 + ')();' }, function(result) {
//         if (result && result[0]) {
//             console.log('The page appears to be a login page.');
//             // console.log("Headers for", details.url);
//             // headers.forEach(function(header) {
//             //     console.log(header.name + ": " + header.value);
//             // });

//             const requestData = {
//                 headers: headers,
//                 entireDOM: htmlContent
//             };

//             console.log("*****************////////////////////////")
//             console.log(requestData)
        
//             // Make the fetch request here, inside the event listener callback
//             console.log('Sending fetch request with headers');
//             fetch('http://localhost:5003/process_data', {
//                 method: 'POST',
//                 headers: {
//                     'Content-Type': 'application/json'
//                 },
//                 body: JSON.stringify(requestData) // Convert data object to JSON string
//             })
//             .then(response => response.json())
//             .then(data => {
//                 if (data == true)
//                 // Handle the response from the server
//                     console.log('Response from server:', "signature verified");
//                 else
//                     console.log('Response from server:', "signature unverified");


//             })
//             .catch(error => {
//                 // Handle errors
//                 console.error('Error:', error);
//             });

//         } else {
//             console.log('The page does not appear to be a login page.');
//         }
//     });
// });


// chrome.webNavigation.onDOMContentLoaded.addListener(function(details) {
//     // Execute isLoginPage function when DOM content is loaded
//     var htmlContent;
//     chrome.tabs.executeScript(details.tabId, { code: 'document.documentElement.outerHTML' }, function(result) {
//         // Check if the result is an array with at least one element
//         if (Array.isArray(result) && result.length > 0) {
//             // Extract the HTML content from the first element of the result array
//             htmlContent = result[0];
            
//             // Process the HTML content here
//             console.log(htmlContent);
//         }
//     });

//     chrome.tabs.executeScript(details.tabId, { code: '(' + isLoginPage2 + ')();' }, function(result) {
//         if (result && result[0]) {
//             console.log('The page appears to be a login page.');
//             // console.log("Headers for", details.url);
//             // headers.forEach(function(header) {
//             //     console.log(header.name + ": " + header.value);
//             // });

//             const requestData = {
//                 headers: headers,
//                 entireDOM: htmlContent
//             };

//             console.log("*****************////////////////////////")
//             console.log(requestData)
        
//             // Make the fetch request here, inside the event listener callback
//             console.log('Sending fetch request with headers');
//             fetch('http://localhost:5003/process_data', {
//                 method: 'POST',
//                 headers: {
//                     'Content-Type': 'application/json'
//                 },
//                 body: JSON.stringify(requestData) // Convert data object to JSON string
//             })
//             .then(response => response.json())
//             .then(data => {
//                 if (data == true)
//                     console.log('Response from server:', "signature verified");
//                 else {
//                     console.log('Response from server:', "signature unverified");
                    
//                     // Call the second API here since the signature is unverified
//                     chrome.tabs.captureVisibleTab(null, { format: "png" }, function(dataUrl) {
//                         if (chrome.runtime.lastError) {
//                             console.error(chrome.runtime.lastError.message);
//                             return;
//                         }
                    
//                         // Send the screenshot to the server
//                         fetch('http://localhost:8000/upload', {
//                             method: 'POST',
//                             body: dataUrl
//                         })
//                         .then(response => {
//                             if (!response.ok) {
//                                 throw new Error('Failed to upload screenshot');
//                             }
//                             // Parse response as text
//                             return response.text();
//                         })
//                         .then(responseText => {
//                             // console.log(responseText,"------------")
//                             // Check if response indicates phishing
//                             if (responseText === 'not phishing') {
//                                 console.log('The screenshot is not phishing.');
//                                 // Handle phishing scenario
//                             } else {
//                                 console.log('The screenshot is phishing.');
//                                 // Handle non-phishing scenario
//                             }
//                         })
//                         .catch(error => {
//                             console.error('Error uploading screenshot:', error);
//                         });
//                     });
//                 }
//             })
//             .catch(error => {
//                 // Handle errors
//                 console.error('Error:', error);
//             });

//         } else {
//             console.log('The page does not appear to be a login page.');
//         }
//     });
// });


chrome.webNavigation.onDOMContentLoaded.addListener(function(details) {
    // Flag to track whether the page should continue loading
    var shouldContinueLoading = false;

    // Execute isLoginPage function when DOM content is loaded
    var htmlContent;
    chrome.tabs.executeScript(details.tabId, { code: 'document.documentElement.outerHTML' }, function(result) {
        // Check if the result is an array with at least one element
        if (Array.isArray(result) && result.length > 0) {
            // Extract the HTML content from the first element of the result array
            htmlContent = result[0];
            
            // Process the HTML content here
            console.log(htmlContent);
        }
    });

    chrome.tabs.executeScript(details.tabId, { code: '(' + isLoginPage2 + ')();' }, function(result) {
        if (result && result[0]) {
            console.log('The page appears to be a login page.');
            // console.log("Headers for", details.url);
            // headers.forEach(function(header) {
            //     console.log(header.name + ": " + header.value);
            // });

            const requestData = {
                headers: headers,
                entireDOM: htmlContent
            };

            console.log("*****************////////////////////////")
            console.log(requestData)
        
            // Make the fetch request here, inside the event listener callback
            console.log('Sending fetch request with headers');
            fetch('http://localhost:5003/process_data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData) // Convert data object to JSON string
            })
            .then(response => response.json())
            .then(data => {
                if (data == "Header not present"){
                    console.log('response from server : header not present')
                    shouldContinueLoading=false
                }
                else if (data == true) {
                    console.log('Response from server:', "signature verified");
                    // Set the flag to continue loading the page
                    shouldContinueLoading = true;
                } else {
                    console.log('Response from server:', "signature unverified");
                    // chrome.tabs.executeScript(details.tabId, { code: 'document.documentElement.innerHTML = "<h1>Wait until we verify the page</h1>";' });

                    shouldContinueLoading = false;
                    // chrome.tabs.executeScript(details.tabId, { code: 'document.write("<h1>This page seems to be phishing.</h1>")' });


                    // Call the second API here since the signature is unverified
                    chrome.tabs.captureVisibleTab(null, { format: "png" }, function(dataUrl) {
                        if (chrome.runtime.lastError) {
                            console.error(chrome.runtime.lastError.message);
                            return;
                        }
                    
                        // Send the screenshot to the server
                        fetch('http://localhost:8000/upload', {
                            method: 'POST',
                            body: dataUrl
                        })
                        .then(response => {
                            if (!response.ok) {
                                throw new Error('Failed to upload screenshot');
                            }
                            // Parse response as text
                            return response.text();
                        })
                        .then(responseText => {
                            console.log(responseText,"------------")
                            // Check if response indicates phishing
                            if (responseText === 'not phishing') {
                                console.log('The screenshot is not phishing.');
                                // chrome.tabs.executeScript(details.tabId, { code: 'document.write("<h1>This page is phishing.</h1>")' });

                                // Handle phishing scenario
                                shouldContinueLoading = true;

                            } else {
                                console.log('The screenshot is phishing.');
                                // Handle non-phishing scenario
                                // Set the flag to stop loading the page
                                shouldContinueLoading = false;

                            }
                        })
                        .catch(error => {
                            console.error('Error uploading screenshot:', error);
                        });
                    });
                }
            })
            .catch(error => {
                // Handle errors
                console.error('Error:', error);
            });

        } else {
            console.log('The page does not appear to be a login page.');
        }
    });

    // Wait for the fetch and processing to complete before deciding whether to continue loading the page
    setTimeout(function() {
        console.log("shouldContinueLoading",  shouldContinueLoading);
        if (!shouldContinueLoading) {
            // Stop loading the page and display phishing warning 
            chrome.tabs.executeScript(details.tabId, { code: 'document.documentElement.innerHTML = "<h1>Dangerr!!! phishing</h1>";' });

            // chrome.tabs.executeScript(details.tabId, { code: 'document.write("<h1>This page is phishing.</h1>")' });
        }
        // else{
        //     console.log(htmlContent);
        //     chrome.tabs.executeScript(details.tabId, { code: 'document.documentElement.innerHTML = `' + htmlContent.replace(/"/g, '\\"') + '`;' });

        // }
    }, 5000); // Adjust the timeout as needed
});
