import React, { useState, useEffect, useRef } from 'react';

function App() {
  const [userInput, setUserInput] = useState('');
  const inputRef = useRef(null);

  const handleInputChange = (event) => {
    setUserInput(event.target.value);
  };

  //dangerous eval usage
  const runDangerousCode = () => {
    const userCode = userInput; //userInput contains code
    eval(userCode); //vulnerable
  };

  useEffect(() => {
    //Direct DOM manipulation
    document.title = userInput;
  }, [userInput]);

  //setTimeout with string argument
  const runSetTimeout = () => {
    setTimeout('alert("This is unsafe!")', 1000); //vulnerable
  };

  //deprecated lifecycle method (simulated in functional component)
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
        ref={inputRef} //insecure ref usage
      />

      {/*unsanitized user input in JSX */}
      <div>{userInput}</div>

      {/*dangerous use of dangerouslySetInnerHTML */}
      <div dangerouslySetInnerHTML={{ __html: userInput }} />

      {/*dangerous JavaScript Execution */}
      <button onClick={runDangerousCode}>
        Run Dangerous Code
      </button>

      {/*setTimeout with string argument */}
      <button onClick={runSetTimeout}>
        Run Unsafe Timeout
      </button>

      {/*dynamic script inclusion */}
      <button
        onClick={() => {
          const script = document.createElement('script');
          script.src = userInput; //vulnerable
          document.body.appendChild(script);
        }}
      >
        Load External Script
      </button>
    </div>
  );
}

export default App;
