Milestone 04 - Final Project Documentation
===

NetID
---
sah8857

Name
---
Sami Hassan

Repository Link
---
Link to repository https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab

URL for deployed site 
---
URL for dpeloyed site: http://linserv1.cims.nyu.edu:35450


URL for form 1 (from previous milestone) 
---
http://linserv1.cims.nyu.edu:35450/login

Special Instructions for Form 1
---
Since the connection is over HTTP it is unsecure. The browser will say the website is unsecure but to proceed click on send any way or other given options.
AuthO is used for the login (for now) and the sign up. No password is stored in the database.
Feel free to use a burner email or any account of the options given. 

URL for form 2 (for current milestone)
---
http://linserv1.cims.nyu.edu:35450/messages

Special Instructions for Form 2
---
The recepient must be someone from your friends so that the message can be sent

URL for form 3 (from previous milestone) 
---
http://linserv1.cims.nyu.edu:35450/profile

Special Instructions for Form 3
---
There is a button called Change Key Password. Click on it to set and change your Key which is used for encryption/decryption.

First link to github line number(s) for constructor, HOF, etc.
---
[Used filter](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/routes/friends.mjs#L46-L72) 

filter was specifically used in line 59


Second link to github line number(s) for constructor, HOF, etc.
---
[Validator function](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/middlewares/validator.mjs#L13-L21) 

Short description for links above
---

Filter:
This line filters the `friendRequests` array to only include requests with a 'pending' status.

Validator function:
This is a higher-order function that we created ourselves. Here's what it does:
- It takes a `schemaName` as an argument.
- It returns a new function that acts as middleware for Express.
- The returned middleware function uses the specified schema to validate the request body.
- If validation fails, it sends a 400 Bad Request response with the error message.
- If validation passes, it calls `next()` to pass control to the next middleware or route handler.

I use this higher-order function to create middleware for validating different types of requests.

For example:

router.post('/setUsername', validator('setUsername'), (req, res) => {
  // Route handler
});

Link to github line number(s) for schemas (db.js or models folder)
---
[Message Schema](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/models/Message.mjs) 

[User Schema](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/models/User.mjs) 

Description of research topics above with points
---
- (6 points) - applied and used AuthO to authenticate users for sign in and sign-up
- (4 points) - used CryptoJS for encrypting and decrypting private keys, messages, and symmetric keys in our secure messaging system. It was crucial for implementing end-to-end encryption, ensuring that messages could only be read by the intended recipients 
- (2 points) - applied Tailwind CSS to give a better look for the website

Links to github line number(s) for research topics described above (one link per line)
---
[AuthO](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/routes/auth.mjs) 

[CryptoJS](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/utils/cryptoUtils.mjs) 

[Tailwind CSS](https://github.com/nyu-csci-ua-0467-001-002-fall-2024/final-project-Sami-Talab/blob/master/views/profile.hbs)

Optional project notes 
--- 
The messages are successfully encrypted and sent but cannot be decrypted due to some bug 

Attributions
---
Tailwind css : https://www.geeksforgeeks.org/tailwind-css/ and ChatGPT
CryptoJS : https://cryptojs.gitbook.io/docs
