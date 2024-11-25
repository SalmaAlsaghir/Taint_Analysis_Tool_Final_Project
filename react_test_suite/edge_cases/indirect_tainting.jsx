// indirect_tainting.jsx

import React, { useState } from 'react';

function IndirectTaintingComponent() {
  const [userInput, setUserInput] = useState('');

  const handleChange = (e) => {
    const temp = e.target.value;
    const sanitizedInput = temp;
    setUserInput(sanitizedInput);  // Tainted data through variables
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

export default IndirectTaintingComponent;
