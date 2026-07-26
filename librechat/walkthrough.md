# Walkthrough - LibreChat Setup with Hugging Face

We have successfully set up LibreChat in a separate, isolated folder `librechat` within your workspace, without making any modifications to the existing `Runtime-shield` code.

Here is the structure created under `librechat/`:
1. **[.env](file:///Users/jashan/Desktop/labs/librechat/.env)**: Environment configuration file, containing pre-generated secure keys (`JWT_SECRET`, `CREDS_KEY`, `CREDS_IV`), database URI mapping, search disable flags, and custom endpoints only options.
2. **[librechat.yaml](file:///Users/jashan/Desktop/labs/librechat/librechat.yaml)**: Configuration file mounting the `HuggingFace` endpoint to the official inference API. It is pre-configured with popular models (such as Llama 3, Gemma, Mistral, and Qwen) and has `dropParams: ["top_p"]` included to ensure compatibility with Hugging Face's inference schema.
3. **[docker-compose.yml](file:///Users/jashan/Desktop/labs/librechat/docker-compose.yml)**: The Docker configuration orchestrating the LibreChat application and its database backend (`mongodb:latest`).

---

## Instructions to Run & Interact

To start interacting with the bot, follow these steps:

### 1. Provide Hugging Face Key
Open the **[.env](file:///Users/jashan/Desktop/labs/librechat/.env)** file and add your Hugging Face API token next to `HUGGINGFACE_TOKEN`:
```env
HUGGINGFACE_TOKEN=your_actual_token_here
```
> [!NOTE]
> You can generate a Hugging Face token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens).

### 2. Start the Docker Containers
In your terminal, navigate to the `librechat` directory and spin up the services:
```bash
cd librechat
docker compose up -d
```
This will pull the images, initialize the MongoDB database, and launch LibreChat.

### 3. Open LibreChat
Open your browser and navigate to:
**[http://localhost:3080](http://localhost:3080)**

### 4. Create an Account
1. Click **Sign Up** to create a local account. Since this is a fresh setup, the first user created will automatically have access.
2. Once logged in, you will see the `HuggingFace` endpoint selected in the dropdown.
3. Select any of the preloaded models (e.g., `meta-llama/Meta-Llama-3-8B-Instruct` or `Qwen/Qwen2.5-7B-Instruct`) and start chatting!

---

## Troubleshooting & Management

- **View Logs**: To inspect the logs and verify requests are reaching Hugging Face:
  ```bash
  docker compose logs -f
  ```
- **Stop services**: To stop the containers without destroying data:
  ```bash
  docker compose down
  ```
- **Reset Database**: If you ever need to reset the setup, you can remove the persistent volume:
  ```bash
  docker compose down -v
  ```
