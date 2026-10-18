"""
Small, deterministic utility functions used by the main project.

Kept separate from intrusion_detection.py so they can be unit-tested
quickly in CI without needing the dataset or training a model
(see Lab Part M — Introduction to GitHub Actions and CI).
"""


def check_overfitting(train_acc, test_acc, threshold=0.05):
    """
    Compare training vs. test accuracy to flag likely overfitting.

    Parameters
    ----------
    train_acc : float
        Accuracy on the training set (0.0 - 1.0).
    test_acc : float
        Accuracy on the test set (0.0 - 1.0).
    threshold : float, default 0.05
        Maximum acceptable gap (train_acc - test_acc) before flagging
        the model as overfitting.

    Returns
    -------
    (gap, is_overfitting) : tuple[float, bool]
        gap: train_acc - test_acc
        is_overfitting: True if gap > threshold
    """
    for name, value in (("train_acc", train_acc), ("test_acc", test_acc)):
        if not (0.0 <= value <= 1.0):
            raise ValueError(f"{name} must be between 0.0 and 1.0, got {value}")

    gap = train_acc - test_acc
    is_overfitting = gap > threshold
    return gap, is_overfitting


def normalize_score(score, maximum):
    """Normalize a raw score to a 0-1 range given its maximum possible value."""
    if maximum <= 0:
        raise ValueError("Maximum must be greater than zero")
    return score / maximum
