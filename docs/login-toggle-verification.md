# Login password toggle verification

The local preview opened on the existing login page without a critical protection banner. The password visibility control rendered at the far right inside the password input and remained vertically centered within the field.

Clicking the control changed the password input type from `password` to `text`, updated the accessible label from `Show password` to `Hide password`, and left the login form and other controls intact. No authentication or credential source files were modified.

A populated test value `Sample#Pass123` was entered, toggled to hidden, and toggled back to visible. The value remained unchanged throughout, while the accessible state changed correctly between `Show password` and `Hide password`.
