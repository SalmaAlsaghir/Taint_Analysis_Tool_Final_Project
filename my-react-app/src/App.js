// App.jsx
import React, { useState, useEffect, useRef } from 'react';

function App() {
  const [userInput, setUserInput] = useState('');
  const inputRef = useRef(null);

  const handleInputChange = (event) => {
    setUserInput(event.target.value);
  };

  // Potentially dangerous eval usage
  const runDangerousCode = () => {
    const userCode = userInput; // Assume userInput contains code
    eval(userCode); // Vulnerable
  };

  useEffect(() => {
    // Direct DOM manipulation
    document.title = userInput;
  }, [userInput]);

  // setTimeout with string argument
  const runSetTimeout = () => {
    setTimeout('alert("This is unsafe!")', 1000); // Vulnerable
  };

  // Deprecated lifecycle method (simulated in functional component)
  useEffect(() => {
    console.warn('componentWillMount equivalent in useEffect');
  }, []);

  return (
    <div>
      <h1>React Vulnerability Testing</h1>

      {/* Input susceptible to XSS */}
      <input
        type="text"
        onChange={handleInputChange}
        placeholder="Enter text"
        ref={inputRef} // Insecure ref usage
      />

      {/* Unsanitized user input in JSX */}
      <div>{userInput}</div>

      {/* Dangerous use of dangerouslySetInnerHTML */}
      <div dangerouslySetInnerHTML={{ __html: userInput }} />

      {/* Dangerous JavaScript Execution */}
      <button onClick={runDangerousCode}>
        Run Dangerous Code
      </button>

      {/* setTimeout with string argument */}
      <button onClick={runSetTimeout}>
        Run Unsafe Timeout
      </button>

      {/* Dynamic script inclusion */}
      <button
        onClick={() => {
          const script = document.createElement('script');
          script.src = userInput; // Vulnerable
          document.body.appendChild(script);
        }}
      >
        Load External Script
      </button>
    </div>
  );
}

export default App;
