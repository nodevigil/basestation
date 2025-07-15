"""
Standardized Result class for consistent API responses.
"""

from typing import TypeVar, Generic, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from enum import Enum

T = TypeVar('T')


class ResultType(Enum):
    """Enumeration of result types for more nuanced result handling."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"


class Result(BaseModel, Generic[T]):
    """
    Standardized result container that returns either data or error.
    
    Usage:
        # Success with data
        result = Result[List[str]].success(['item1', 'item2'], meta={'count': 2})
        
        # Error
        result = Result[str].from_error('Something went wrong')
        
        # Warning
        result = Result[str].warning('Partial success', data)
        
        # Check result
        if result.is_success():
            data = result.data
        else:
            error = result.error
    """
    
    data: Optional[T] = None
    error: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    result_type: ResultType = ResultType.SUCCESS
    
    class Config:
        arbitrary_types_allowed = True
    
    @classmethod
    def success(cls, data: T, meta: Optional[Dict[str, Any]] = None) -> 'Result[T]':
        """Create a successful result with data."""
        return cls(data=data, meta=meta, result_type=ResultType.SUCCESS)
    
    @classmethod
    def from_error(cls, error: str, meta: Optional[Dict[str, Any]] = None) -> 'Result[T]':
        """Create an error result."""
        return cls(error=error, meta=meta, result_type=ResultType.ERROR)
    
    @classmethod
    def warning(cls, error: str, data: Optional[T] = None, meta: Optional[Dict[str, Any]] = None) -> 'Result[T]':
        """Create a warning result (partial success with issues)."""
        return cls(data=data, error=error, meta=meta, result_type=ResultType.WARNING)
    
    def is_success(self) -> bool:
        """Check if result is successful (has data, no error)."""
        return self.result_type == ResultType.SUCCESS and self.error is None and self.data is not None
    
    def is_error(self) -> bool:
        """Check if result is an error."""
        return self.result_type == ResultType.ERROR
    
    def is_warning(self) -> bool:
        """Check if result is a warning (partial success)."""
        return self.result_type == ResultType.WARNING
    
    def has_issues(self) -> bool:
        """Check if result has any issues (error or warning)."""
        return self.result_type in (ResultType.ERROR, ResultType.WARNING)
    
    def unwrap(self) -> T:
        """
        Get data if successful, raise exception if error.
        
        Raises:
            ValueError: If result contains an error
        """
        if self.is_error():
            raise ValueError(f"Result contains error: {self.error}")
        return self.data
    
    def unwrap_or(self, default: T) -> T:
        """Get data if successful, return default if error."""
        return self.data if self.is_success() else default
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        if self.is_error():
            result = {"error": self.error}
        elif self.is_warning():
            result = {"error": self.error}  # Include warning message as error
            if self.data is not None:
                # Convert data to dict if it's a Pydantic model, otherwise use as-is
                data_dict = self.data
                if hasattr(self.data, 'dict'):
                    data_dict = self.data.dict()
                elif hasattr(self.data, '__dict__'):
                    data_dict = self.data.__dict__
                result["data"] = data_dict
        else:
            # Convert data to dict if it's a Pydantic model, otherwise use as-is
            data_dict = self.data
            if hasattr(self.data, 'dict'):
                data_dict = self.data.dict()
            elif hasattr(self.data, '__dict__'):
                data_dict = self.data.__dict__
            
            # If data is already structured with "data" and "meta" keys, use it directly
            if isinstance(data_dict, dict) and "data" in data_dict and "meta" in data_dict:
                return data_dict
            
            result = {"data": data_dict}
        
        if self.meta:
            result["meta"] = self.meta
        return result
    
    def as_dict(self) -> Dict[str, Any]:
        """Alias for to_dict() for consistency."""
        return self.to_dict()
    
    def to_json(self, **kwargs) -> str:
        """Convert to JSON string."""
        import json
        return json.dumps(self.to_dict(), **kwargs)
    
    def __str__(self) -> str:
        """String representation of the Result."""
        return self.to_json()
    
    def __repr__(self) -> str:
        """Detailed representation of the Result."""
        if self.is_error():
            return f"Result(error={self.error!r})"
        else:
            return f"Result(data={self.data!r}, meta={self.meta!r})"


# Type aliases for common use cases
StrResult = Result[str]
DictResult = Result[Dict[str, Any]]
ListResult = Result[list]
BoolResult = Result[bool]
IntResult = Result[int]
