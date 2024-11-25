// vulnerable_eval.jsx

import React, { useState } from 'react';

function VulnerableEvalComponent() {
  const [userInput, setUserInput] = useState('');

  const handleChange = (e) => {
    setUserInput(e.target.value);  // Tainted data
  };

  const executeUserCode = () => {
    eval(userInput);  // Dangerous use of eval
  };

  return (
    <div>
      <input type="text" onChange={handleChange} />
      <button onClick={executeUserCode}>Run Code</button>
    </div>
  );
}

export default VulnerableEvalComponent;
