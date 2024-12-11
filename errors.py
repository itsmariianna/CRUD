from fastapi import HTTPException

# Base error class for inheritance
class BaseAppError(Exception):
    def __init__(self, message: str, status_code: int):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# Validation-related errors
class ValidationError(BaseAppError):
    def __init__(self, message: str):
        super().__init__(message, status_code=400)


# File handling errors
class FileError(BaseAppError):
    def __init__(self, message: str):
        super().__init__(message, status_code=500)


# Not Found errors
class NotFoundError(BaseAppError):
    def __init__(self, message: str):
        super().__init__(message, status_code=404)


# FastAPI Exception Translator
def raise_fastapi_exception(error: BaseAppError):
    raise HTTPException(status_code=error.status_code, detail=error.message)
