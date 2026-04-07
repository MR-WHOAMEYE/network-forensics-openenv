from server.gradio_ui import create_demo


demo = create_demo()


if __name__ == "__main__":
    demo.launch(server_port=7860, server_name="0.0.0.0")
