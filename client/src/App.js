import React, { useState, useEffect } from 'react';
import './App.css';

const CLIENT_ID = '529326706888-8h1r3o9o1e88pitbkj3s4l30ib86fk08.apps.googleusercontent.com';
const SCOPES = 'https://www.googleapis.com/auth/gmail.modify';
// const SCOPES = 'profile';



const EmailForm = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
  });

  useEffect(() => {
    const loadGoogleApiScript = () => {
      const script = document.createElement('script');
      script.src = 'https://apis.google.com/js/api.js';
      script.onload = () => {
        window.gapi.load('client:auth2', initClient);
      };
      script.onerror = () => {
        console.error('Failed to load the Google API script');
      };
      document.body.appendChild(script);
    };

    loadGoogleApiScript();
  }, []);

  const initClient = () => {
    window.gapi.client.init({
      clientId: CLIENT_ID,
      scope: SCOPES,
      apiKey:"AIzaSyBSlIpe8vDnuBE8FtD-aFbLwe__RWQ4iRc",
    }).then((res) => {
      window.gapi.auth2.getAuthInstance().isSignedIn.listen(updateSigninStatus);
      console.log(res)
    }).catch((error) => {
      console.error('Error initializing Google API client:', error);
    });
  };

  const updateSigninStatus = (isSignedIn) => {
    if (isSignedIn) {
      handleSubmit();
    }
  };

  const handleAuthClick = () => {
    window.gapi.auth2.getAuthInstance().signIn().catch((error) => {
      console.error('Error signing in:', error);
    });
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleSubmit = () => {
    const authInstance = window.gapi.auth2.getAuthInstance();
    const user = authInstance.currentUser.get();
    const authResponse = user.getAuthResponse();

    console.log('Token:', authResponse.access_token); // Print the token to the console

    const dataToSend = {
      ...formData,
      token: authResponse.access_token,
    };

    fetch('https://e492-171-76-87-74.ngrok-free.app/add_user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': '69420',
      },
      body: JSON.stringify(dataToSend),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log('Success:', data);
      })
      .catch((error) => {
        console.error('Error:', error);
      });
  };

  return (
    <div className="form-container">
      <form onSubmit={(e) => e.preventDefault()}>
        <label>
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
            required
            placeholder="ENTER NAME"
          />
        </label>
        <label>
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            required
            placeholder="ENTER EMAIL ID"
          />
        </label>
        <button type="button" onClick={handleAuthClick}>Submit</button>
      </form>
    </div>
  );
};

export default EmailForm;
