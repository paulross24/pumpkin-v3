class FeedbackLogger:
    def __init__(self):
        self.logs = []

    def log_feedback(self, user_id: str, feedback: str):
        self.logs.append({'user_id': user_id, 'feedback': feedback})

    def summarize_feedback(self):
        # Summarize feedback for analysis
        return self.logs

feedback_logger = FeedbackLogger()

def receive_user_feedback(user_id: str, feedback: str):
    feedback_logger.log_feedback(user_id, feedback)
