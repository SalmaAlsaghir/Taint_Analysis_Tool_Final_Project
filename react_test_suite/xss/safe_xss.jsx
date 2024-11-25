// safe_xss.jsx

import React, { useState } from 'react';
import DOMPurify from 'dompurify';

function SafeXSSComponent() {
  const [userInput, setUserInput] = useState('');

  const handleChange = (e) => {
    const sanitizedInput = DOMPurify.sanitize(e.target.value);
    setUserInput(sanitizedInput);  // Sanitized data
  };

  return (
    <div>
      <input type="text" onChange={handleChange} />
      <div dangerouslySetInnerHTML={{ __html: userInput }} />  {/* Safe rendering */}
    </div>
  );
}

export default SafeXSSComponent;
