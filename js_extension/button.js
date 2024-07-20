function createDefaultButton() {
    const button = document.createElement('button');
    button.textContent = 'Run Asterio!';
    button.id = 'extractArtifactsButton';
    button.style.position = 'fixed';
    button.style.bottom = '10px';
    button.style.right = '10px';
    button.style.zIndex = '1000';
    button.style.padding = '10px';
    button.style.backgroundColor = '#007bff';
    button.style.color = '#fff';
    button.style.border = 'none';
    button.style.borderRadius = '5px';
    button.style.cursor = 'pointer';

    document.body.appendChild(button);
}

// Automatically create the button when this script is injected
createDefaultButton();