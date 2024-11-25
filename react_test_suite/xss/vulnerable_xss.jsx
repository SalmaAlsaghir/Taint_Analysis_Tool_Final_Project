import React, { useState } from 'react';

function VulnerableXSSComponent() {
  const [userInput, setUserInput] = useState('');

  const handleChange = (e) => {
    setUserInput(e.target.value);  //tainted data
  };

  return (
    <div>
      <input type="text" onChange={handleChange} />
      <div dangerouslySetInnerHTML={{ __html: userInput }} />  {/* Vulnerable to XSS */}
    </div>
  );
}

export default VulnerableXSSComponent;
