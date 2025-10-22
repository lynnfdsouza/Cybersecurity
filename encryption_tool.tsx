import React, { useState } from 'react';
import { Lock, Unlock, FileText, MessageSquare, Copy, Download, Upload, Eye, EyeOff, AlertCircle } from 'lucide-react';

const EncryptionTool = () => {
  const [mode, setMode] = useState('text');
  const [operation, setOperation] = useState('encrypt');
  const [input, setInput] = useState('');
  const [password, setPassword] = useState('');
  const [output, setOutput] = useState('');
  const [fileName, setFileName] = useState('');
  const [fileData, setFileData] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [processing, setProcessing] = useState(false);

  // Convert ArrayBuffer to base64
  const arrayBufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  // Convert base64 to ArrayBuffer
  const base64ToArrayBuffer = (base64) => {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };

  // Derive key from password
  const deriveKey = async (password, salt) => {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  };

  // Encrypt data (works with both text and binary)
  const encryptData = async (data, password) => {
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(password, salt);
      
      // Convert string to ArrayBuffer if needed
      let dataBuffer;
      if (typeof data === 'string') {
        const enc = new TextEncoder();
        dataBuffer = enc.encode(data);
      } else {
        dataBuffer = data;
      }
      
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        dataBuffer
      );
      
      // Combine salt + iv + encrypted data
      const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
      combined.set(salt, 0);
      combined.set(iv, salt.length);
      combined.set(new Uint8Array(encrypted), salt.length + iv.length);
      
      return arrayBufferToBase64(combined);
    } catch (err) {
      throw new Error('Encryption failed: ' + err.message);
    }
  };

  // Decrypt data
  const decryptData = async (encryptedData, password, returnAsText = true) => {
    try {
      const combined = new Uint8Array(base64ToArrayBuffer(encryptedData));
      
      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const data = combined.slice(28);
      
      const key = await deriveKey(password, salt);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
      );
      
      if (returnAsText) {
        const dec = new TextDecoder();
        return dec.decode(decrypted);
      } else {
        return decrypted;
      }
    } catch (err) {
      throw new Error('Decryption failed. Check your password and make sure you\'re using the correct encrypted data.');
    }
  };

  const handleProcess = async () => {
    setError('');
    setOutput('');
    setProcessing(true);
    
    if (mode === 'text' && !input.trim()) {
      setError('Please enter some text to process');
      setProcessing(false);
      return;
    }
    
    if (mode === 'file' && !fileData && operation === 'encrypt') {
      setError('Please upload a file first');
      setProcessing(false);
      return;
    }
    
    if (mode === 'file' && !input.trim() && operation === 'decrypt') {
      setError('Please paste the encrypted data');
      setProcessing(false);
      return;
    }
    
    if (!password) {
      setError('Please enter a password');
      setProcessing(false);
      return;
    }
    
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      setProcessing(false);
      return;
    }
    
    try {
      if (operation === 'encrypt') {
        if (mode === 'text') {
          const encrypted = await encryptData(input, password);
          setOutput(encrypted);
        } else {
          // Encrypt file
          const encrypted = await encryptData(fileData, password);
          setOutput(encrypted);
        }
      } else {
        // Decrypt
        if (mode === 'text') {
          const decrypted = await decryptData(input, password, true);
          setOutput(decrypted);
        } else {
          // Decrypt file - store as binary
          const decrypted = await decryptData(input, password, false);
          setFileData(decrypted);
          setOutput('File decrypted successfully! Click Download to save.');
        }
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setProcessing(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    setFileName(file.name);
    setError('');
    
    try {
      if (operation === 'encrypt') {
        // For encryption, read as ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();
        setFileData(arrayBuffer);
        setInput(`File loaded: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`);
      } else {
        // For decryption, read as text (base64)
        const text = await file.text();
        setInput(text);
      }
    } catch (err) {
      setError('Failed to read file: ' + err.message);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  const handleDownload = () => {
    try {
      if (mode === 'file' && operation === 'decrypt' && fileData) {
        // Download decrypted binary file
        const blob = new Blob([fileData]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        // Remove .encrypted.txt extension to restore original filename
        let downloadName = fileName;
        if (downloadName.endsWith('.encrypted.txt')) {
          downloadName = downloadName.replace('.encrypted.txt', '');
        } else if (downloadName.endsWith('.encrypted')) {
          downloadName = downloadName.replace('.encrypted', '');
        }
        a.download = downloadName || 'decrypted_file';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 100);
      } else {
        // Download text output
        const blob = new Blob([output], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = operation === 'encrypt' ? 
          (fileName ? fileName + '.encrypted.txt' : 'encrypted.txt') :
          (fileName ? fileName.replace('.encrypted.txt', '.txt') : 'decrypted.txt');
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 100);
      }
    } catch (err) {
      setError('Download failed: ' + err.message);
    }
  };

  const handleModeChange = (newMode) => {
    setMode(newMode);
    setInput('');
    setOutput('');
    setFileData(null);
    setFileName('');
    setError('');
  };

  const handleOperationChange = (newOp) => {
    setOperation(newOp);
    setInput('');
    setOutput('');
    setFileData(null);
    setFileName('');
    setError('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Lock className="w-12 h-12 text-purple-400" />
            <h1 className="text-4xl font-bold text-white">AES-256 Encryption Tool</h1>
          </div>
          <p className="text-purple-200">Military-grade encryption for your documents and messages</p>
        </div>

        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 shadow-2xl border border-white/20">
          {/* Mode Selection */}
          <div className="flex gap-4 mb-6">
            <button
              onClick={() => handleModeChange('text')}
              className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
                mode === 'text'
                  ? 'bg-purple-500 text-white shadow-lg'
                  : 'bg-white/5 text-white/70 hover:bg-white/10'
              }`}
            >
              <MessageSquare className="w-5 h-5" />
              Text/Message
            </button>
            <button
              onClick={() => handleModeChange('file')}
              className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
                mode === 'file'
                  ? 'bg-purple-500 text-white shadow-lg'
                  : 'bg-white/5 text-white/70 hover:bg-white/10'
              }`}
            >
              <FileText className="w-5 h-5" />
              File/Document
            </button>
          </div>

          {/* Operation Selection */}
          <div className="flex gap-4 mb-6">
            <button
              onClick={() => handleOperationChange('encrypt')}
              className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
                operation === 'encrypt'
                  ? 'bg-green-500 text-white shadow-lg'
                  : 'bg-white/5 text-white/70 hover:bg-white/10'
              }`}
            >
              <Lock className="w-5 h-5" />
              Encrypt
            </button>
            <button
              onClick={() => handleOperationChange('decrypt')}
              className={`flex-1 py-3 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
                operation === 'decrypt'
                  ? 'bg-blue-500 text-white shadow-lg'
                  : 'bg-white/5 text-white/70 hover:bg-white/10'
              }`}
            >
              <Unlock className="w-5 h-5" />
              Decrypt
            </button>
          </div>

          {/* File Upload */}
          {mode === 'file' && (
            <div className="mb-6">
              <label className="block w-full p-4 border-2 border-dashed border-purple-400/50 rounded-lg text-center cursor-pointer hover:border-purple-400 transition-colors bg-white/5">
                <Upload className="w-8 h-8 mx-auto mb-2 text-purple-400" />
                <span className="text-white/90 block">
                  {fileName || (operation === 'encrypt' ? 'Click to upload file to encrypt' : 'Click to upload encrypted file (.encrypted.txt)')}
                </span>
                {operation === 'encrypt' && (
                  <span className="text-white/50 text-sm block mt-1">
                    Supports: Word docs, PDFs, images, any file type
                  </span>
                )}
                <input
                  type="file"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          )}

          {/* Input - Text mode or Decrypt mode */}
          {(mode === 'text' || (mode === 'file' && operation === 'decrypt')) && (
            <div className="mb-6">
              <label className="block text-white/90 font-semibold mb-2">
                {operation === 'encrypt' ? 'Text to Encrypt' : 'Encrypted Data'}
              </label>
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={operation === 'encrypt' ? 
                  'Enter your sensitive text here...' : 
                  'Paste encrypted text here...'}
                className="w-full h-40 bg-white/10 text-white rounded-lg p-4 border border-white/20 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-400/50 font-mono text-sm"
                readOnly={mode === 'file' && operation === 'encrypt'}
              />
            </div>
          )}

          {/* Password */}
          <div className="mb-6">
            <label className="block text-white/90 font-semibold mb-2">
              Password (min 8 characters)
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter a strong password"
                className="w-full bg-white/10 text-white rounded-lg p-4 pr-12 border border-white/20 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-400/50"
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-white/50 hover:text-white/90"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {/* Process Button */}
          <button
            onClick={handleProcess}
            disabled={processing}
            className={`w-full py-4 rounded-lg font-bold text-white shadow-lg transition-all ${
              processing ? 'bg-gray-500 cursor-not-allowed' :
              operation === 'encrypt'
                ? 'bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700'
                : 'bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700'
            }`}
          >
            {processing ? 'Processing...' : operation === 'encrypt' ? 'Encrypt Data' : 'Decrypt Data'}
          </button>

          {/* Error Message */}
          {error && (
            <div className="mt-6 p-4 bg-red-500/20 border border-red-500/50 rounded-lg text-red-200 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Output */}
          {output && (
            <div className="mt-6">
              <label className="block text-white/90 font-semibold mb-2">
                {operation === 'encrypt' ? 'Encrypted Result' : 'Decrypted Result'}
              </label>
              <div className="relative">
                <textarea
                  value={output}
                  readOnly
                  className="w-full h-40 bg-white/10 text-white rounded-lg p-4 border border-white/20 font-mono text-sm"
                />
                <div className="flex gap-2 mt-2">
                  {!(mode === 'file' && operation === 'decrypt' && fileData) && (
                    <button
                      onClick={handleCopy}
                      className="flex-1 py-2 px-4 bg-purple-500 hover:bg-purple-600 text-white rounded-lg font-semibold flex items-center justify-center gap-2 transition-all"
                    >
                      <Copy className="w-4 h-4" />
                      Copy
                    </button>
                  )}
                  <button
                    onClick={handleDownload}
                    className="flex-1 py-2 px-4 bg-purple-500 hover:bg-purple-600 text-white rounded-lg font-semibold flex items-center justify-center gap-2 transition-all"
                  >
                    <Download className="w-4 h-4" />
                    Download
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Instructions */}
          <div className="mt-6 p-4 bg-blue-500/20 border border-blue-400/30 rounded-lg">
            <h3 className="text-blue-200 font-semibold mb-2">📝 How to use with files:</h3>
            <ul className="text-blue-100 text-sm space-y-1">
              <li><strong>Encrypt:</strong> Upload any file → Enter password → Click Encrypt → Download the .encrypted.txt file</li>
              <li><strong>Decrypt:</strong> Upload the .encrypted.txt file → Enter same password → Click Decrypt → Download original file</li>
              <li>⚠️ Save your password securely! You cannot decrypt without it.</li>
            </ul>
          </div>

          {/* Security Info */}
          <div className="mt-4 p-4 bg-purple-500/20 border border-purple-400/30 rounded-lg">
            <h3 className="text-purple-200 font-semibold mb-2">🔒 Security Features</h3>
            <ul className="text-purple-100 text-sm space-y-1">
              <li>• AES-256-GCM encryption (military-grade)</li>
              <li>• PBKDF2 key derivation with 100,000 iterations</li>
              <li>• Random salt and IV for each encryption</li>
              <li>• All processing happens locally in your browser</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EncryptionTool;