import {
  Block,
  CloseRounded,
  EmailRounded,
  Visibility,
  VisibilityOff,
  PasswordRounded,
  TroubleshootRounded,
} from "@mui/icons-material";
import React, { useState, useEffect } from "react";
import styled from "styled-components";
import { IconButton, Modal } from "@mui/material";
import CircularProgress from "@mui/material/CircularProgress";
import { loginFailure, loginStart, loginSuccess } from "../redux/userSlice";
import { openSnackbar } from "../redux/snackbarSlice";
import { useDispatch } from "react-redux";
import validator from "validator";
import { signIn, googleSignIn, findUserByEmail, resetPassword } from "../api/index";
import OTP from "./OTP";
import { useGoogleLogin } from "@react-oauth/google";
import axios from "axios";
import { closeSignin } from "../redux/setSigninSlice";


const Container = styled.div`
    width: 100%;
    height: 100%;
    position: absolute;
    top: 0;
    left: 0;
    background-color: #000000a7;
    display: flex;
    align-items: center;
    justify-content: center;
  `;

const Wrapper = styled.div`
    width: 380px;
    border-radius: 16px;
    background-color: ${({ theme }) => theme.card};
    color: ${({ theme }) => theme.text_primary};
    padding: 10px;
    display: flex;
    flex-direction: column;
    position: relative;
  `;

const Title = styled.div`
    font-size: 22px;
    font-weight: 500;
    color: ${({ theme }) => theme.text_primary};
    margin: 16px 28px;
  `;
const OutlinedBox = styled.div`
    height: 44px;
    border-radius: 12px;
    border: 1px solid ${({ theme }) => theme.text_secondary};
    color: ${({ theme }) => theme.text_secondary};
    ${({ googleButton, theme }) =>
    googleButton &&
    `
      user-select: none; 
    gap: 16px;`}
    ${({ button, theme }) =>
    button &&
    `
      user-select: none; 
    border: none;
      background: ${theme.button};
      color:'${theme.bg}';`}
      ${({ activeButton, theme }) =>
    activeButton &&
    `
      user-select: none; 
    border: none;
      background: ${theme.primary};
      color: white;`}
    margin: 3px 20px;
    font-size: 14px;
    display: flex;
    justify-content: center;
    align-items: center;
    font-weight: 500;
    padding: 0px 14px;
  `;
const GoogleIcon = styled.img`
    width: 22px;
  `;
const Divider = styled.div`
    display: flex;
    display: flex;
    justify-content: center;
    align-items: center;
    color: ${({ theme }) => theme.text_secondary};
    font-size: 14px;
    font-weight: 600;
  `;
const Line = styled.div`
    width: 80px;
    height: 1px;
    border-radius: 10px;
    margin: 0px 10px;
    background-color: ${({ theme }) => theme.text_secondary};
  `;

const TextInput = styled.input`
    width: 100%;
    border: none;
    font-size: 14px;
    border-radius: 3px;
    background-color: transparent;
    outline: none;
    color: ${({ theme }) => theme.text_secondary};
  `;

const LoginText = styled.div`
    font-size: 14px;
    font-weight: 500;
    color: ${({ theme }) => theme.text_secondary};
    margin: 20px 20px 30px 20px;
    display: flex;
    justify-content: center;
    align-items: center;
  `;
const Span = styled.span`
    color: ${({ theme }) => theme.primary};
  `;

const Error = styled.div`
    color: red;
    font-size: 10px;
    margin: 2px 26px 8px 26px;
    display: block;
    ${({ error, theme }) =>
    error === "" &&
    `    display: none;
      `}
  `;

const ForgetPassword = styled.div`
    color: ${({ theme }) => theme.text_secondary};
    font-size: 13px;
    margin: 8px 26px;
    display: block;
    cursor: pointer;
    text-align: right;
    &:hover {
      color: ${({ theme }) => theme.primary};
    }
    `;

const SignIn = ({ setSignInOpen, setSignUpOpen }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [Loading, setLoading] = useState(false);
  const [disabled, setDisabled] = useState(true);
  const [values, setValues] = useState({
    password: "",
    showPassword: false,
  });

  //verify otp
  const [showOTP, setShowOTP] = useState(false);
  const [otpVerified, setOtpVerified] = useState(false);
  //reset password
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [samepassword, setSamepassword] = useState("");
  const [newpassword, setNewpassword] = useState("");
  const [confirmedpassword, setConfirmedpassword] = useState("");
  const [passwordCorrect, setPasswordCorrect] = useState(false);
  const [resetDisabled, setResetDisabled] = useState(true);
  const [resettingPassword, setResettingPassword] = useState(false);
  const dispatch = useDispatch();

  useEffect(() => {
    if (email !== "") validateEmail();
    if (validator.isEmail(email) && password.length > 5) {
      setDisabled(false);
    } else {
      setDisabled(true);
    }
  }, [email, password]);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!disabled) {
      dispatch(loginStart());
      setDisabled(true);
      setLoading(true);
      try {
        signIn({ email, password }).then((res) => {
          if (res.status === 200) {
            dispatch(loginSuccess(res.data));
            setLoading(false);
            setDisabled(false);
            dispatch(
              closeSignin()
            )
            dispatch(
              openSnackbar({
                message: "Logged In Successfully",
                severity: "success",
              })
            );
          } else if (res.status === 203) {
            dispatch(loginFailure());
            setLoading(false);
            setDisabled(false);
            setcredentialError(res.data.message);
            dispatch(
              openSnackbar({
                message: "Account Not Verified",
                severity: "error",
              })
            );
          } else {
            dispatch(loginFailure());
            setLoading(false);
            setDisabled(false);
            setcredentialError(`Invalid Credentials : ${res.data.message}`);
          }
        });
      } catch (err) {
        dispatch(loginFailure());
        setLoading(false);
        setDisabled(false);
        dispatch(
          openSnackbar({
            message: err.message,
            severity: "error",
          })
        );
      }
    }
    if (email === "" || password === "") {
      dispatch(
        openSnackbar({
          message: "Please fill all the fields",
          severity: "error",
        })
      );
    }
  };

  const [emailError, setEmailError] = useState("");
  const [credentialError, setcredentialError] = useState("");

  const validateEmail = () => {
    if (validator.isEmail(email)) {
      setEmailError("");
    } else {
      setEmailError("Enter a valid Email Id!");
    }
  };


  //validate password
  const validatePassword = () => {
    if (newpassword.length < 8) {
      setSamepassword("Password must be atleast 8 characters long!");
      setPasswordCorrect(false);
    } else if (newpassword.length > 16) {
      setSamepassword("Password must be less than 16 characters long!");
      setPasswordCorrect(false);
    } else if (
      !newpassword.match(/[a-z]/g) ||
      !newpassword.match(/[A-Z]/g) ||
      !newpassword.match(/[0-9]/g) ||
      !newpassword.match(/[^a-zA-Z\d]/g)
    ) {
      setPasswordCorrect(false);
      setSamepassword(
        "Password must contain atleast one lowercase, uppercase, number and special character!"
      );
    }
    else {
      setSamepassword("");
      setPasswordCorrect(true);
    }
  };

  useEffect(() => {
    if (newpassword !== "") validatePassword();
    if (
      passwordCorrect
      && newpassword === confirmedpassword
    ) {
      setSamepassword("");
      setResetDisabled(false);
    } else if (confirmedpassword !== "" && passwordCorrect) {
      setSamepassword("Passwords do not match!");
      setResetDisabled(true);
    }
  }, [newpassword, confirmedpassword]);

  const sendOtp = () => {
    if (!resetDisabled) {
      setResetDisabled(true);
      setLoading(true);
      findUserByEmail(email).then((res) => {
        if (res.status === 200) {
          setShowOTP(true);
          setResetDisabled(false);
          setLoading(false);
        }
        else if (res.status === 202) {
          setEmailError("User not found!")
          setResetDisabled(false);
          setLoading(false);
        }
      }).catch((err) => {
        setResetDisabled(false);
        setLoading(false);
        dispatch(
          openSnackbar({
            message: err.message,
            severity: "error",
          })
        );
      });
    }
  }

  const performResetPassword = async () => {
    if (otpVerified) {
      setShowOTP(false);
      setResettingPassword(true);
      await resetPassword(email, confirmedpassword).then((res) => {
        if (res.status === 200) {
          dispatch(
            openSnackbar({
              message: "Password Reset Successfully",
              severity: "success",
            })
          );
          setShowForgotPassword(false);
          setEmail("");
          setNewpassword("");
          setConfirmedpassword("");
          setOtpVerified(false);
          setResettingPassword(false);
        }
      }).catch((err) => {
        dispatch(
          openSnackbar({
            message: err.message,
            severity: "error",
          })
        );
        setShowOTP(false);
        setOtpVerified(false);
        setResettingPassword(false);
      });
    }
  }
  const closeForgetPassword = () => {
    setShowForgotPassword(false)
    setShowOTP(false)
  }
  useEffect(() => {
    performResetPassword();
  }, [otpVerified]);


  //Google SignIn
  const googleLogin = useGoogleLogin({
    onSuccess: async (tokenResponse) => {
      setLoading(true);
      const user = await axios.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        { headers: { Authorization: `Bearer ${tokenResponse.access_token}` } },
      ).catch((err) => {
        dispatch(loginFailure());
        dispatch(
          openSnackbar({
            message: err.message,
            severity: "error",
          })
        );
      });

      googleSignIn({
        name: user.data.name,
        email: user.data.email,
        img: user.data.picture,
      }).then((res) => {
        console.log(res);
        if (res.status === 200) {
          dispatch(loginSuccess(res.data));
          dispatch(
            closeSignin()
          );
          dispatch(
            openSnackbar({
              message: "Logged In Successfully",
              severity: "success",
            })
          );
          setLoading(false);
        } else {
          dispatch(loginFailure(res.data));
          dispatch(
            openSnackbar({
              message: res.data.message,
              severity: "error",
            })
          );
          setLoading(false);
        }
      });
    },
    onError: errorResponse => {
      dispatch(loginFailure());
      setLoading(false);
      dispatch(
        openSnackbar({
          message: errorResponse.error,
          severity: "error",
        })
      );
    },
  });


  return (
    <Modal open={true} onClose={() => dispatch(
      closeSignin()
    )}>
      <Container>
        {!showForgotPassword ? (
          <Wrapper>
            <CloseRounded
              style={{
                position: "absolute",
                top: "24px",
                right: "30px",
                cursor: "pointer",
              }}
              onClick={() => dispatch(
                closeSignin()
              )}
            />
            <>
              <Title>Sign In</Title>
              <OutlinedBox
                googleButton={TroubleshootRounded}
                style={{ margin: "24px" }}
                onClick={() => googleLogin()}
              >
                {Loading ? (
                  <CircularProgress color="inherit" size={20} />
                ) : (
                  <>
                    <GoogleIcon src="data:image/jpeg;base64,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" />
                    Sign In with Google</>
                )}
              </OutlinedBox>
              <Divider>
                <Line />
                or
                <Line />
              </Divider>
              <OutlinedBox style={{ marginTop: "24px" }}>
                <EmailRounded
                  sx={{ fontSize: "20px" }}
                  style={{ paddingRight: "12px" }}
                />
                <TextInput
                  placeholder="Email Id"
                  type="email"
                  onChange={(e) => setEmail(e.target.value)}
                />
              </OutlinedBox>
              <Error error={emailError}>{emailError}</Error>
              <OutlinedBox>
                <PasswordRounded
                  sx={{ fontSize: "20px" }}
                  style={{ paddingRight: "12px" }}
                />
                <TextInput
                  placeholder="Password"
                  type={values.showPassword ? "text" : "password"}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <IconButton
                  color="inherit"
                  onClick={() =>
                    setValues({ ...values, showPassword: !values.showPassword })
                  }
                >
                  {values.showPassword ? (
                    <Visibility sx={{ fontSize: "20px" }} />
                  ) : (
                    <VisibilityOff sx={{ fontSize: "20px" }} />
                  )}
                </IconButton>
              </OutlinedBox>
              <Error error={credentialError}>{credentialError}</Error>
              <ForgetPassword onClick={() => { setShowForgotPassword(true) }}><b>Forgot password ?</b></ForgetPassword>
              <OutlinedBox
                button={true}
                activeButton={!disabled}
                style={{ marginTop: "6px" }}
                onClick={handleLogin}
              >
                {Loading ? (
                  <CircularProgress color="inherit" size={20} />
                ) : (
                  "Sign In"
                )}
              </OutlinedBox>
            </>
            <LoginText>
              Don't have an account ?
              <Span
                onClick={() => {
                  setSignUpOpen(true);
                  dispatch(
                    closeSignin({

                    })
                  );
                }}
                style={{
                  fontWeight: "500",
                  marginLeft: "6px",
                  cursor: "pointer",
                }}
              >
                Create Account
              </Span>
            </LoginText>
          </Wrapper>
        ) : (
          <Wrapper>
            <CloseRounded
              style={{
                position: "absolute",
                top: "24px",
                right: "30px",
                cursor: "pointer",
              }}
              onClick={() => { closeForgetPassword() }}
            />
            {!showOTP ?
              <>
                <Title>Reset Password</Title>
                {resettingPassword ?
                  <div style={{ padding: '12px 26px', marginBottom: '20px', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px', justifyContent: 'center' }}>Updating password<CircularProgress color="inherit" size={20} /></div>
                  :
                  <>

                    <OutlinedBox style={{ marginTop: "24px" }}>
                      <EmailRounded
                        sx={{ fontSize: "20px" }}
                        style={{ paddingRight: "12px" }}
                      />
                      <TextInput
                        placeholder="Email Id"
                        type="email"
                        onChange={(e) => setEmail(e.target.value)}
                      />
                    </OutlinedBox>
                    <Error error={emailError}>{emailError}</Error>
                    <OutlinedBox>
                      <PasswordRounded
                        sx={{ fontSize: "20px" }}
                        style={{ paddingRight: "12px" }}
                      />
                      <TextInput
                        placeholder="New Password"
                        type="text"
                        onChange={(e) => setNewpassword(e.target.value)}
                      />
                    </OutlinedBox>
                    <OutlinedBox>
                      <PasswordRounded
                        sx={{ fontSize: "20px" }}
                        style={{ paddingRight: "12px" }}
                      />
                      <TextInput
                        placeholder="Confirm Password"
                        type={values.showPassword ? "text" : "password"}
                        onChange={(e) => setConfirmedpassword(e.target.value)}
                      />
                      <IconButton
                        color="inherit"
                        onClick={() =>
                          setValues({ ...values, showPassword: !values.showPassword })
                        }
                      >
                        {values.showPassword ? (
                          <Visibility sx={{ fontSize: "20px" }} />
                        ) : (
                          <VisibilityOff sx={{ fontSize: "20px" }} />
                        )}
                      </IconButton>
                    </OutlinedBox>
                    <Error error={samepassword}>{samepassword}</Error>
                    <OutlinedBox
                      button={true}
                      activeButton={!resetDisabled}
                      style={{ marginTop: "6px", marginBottom: "24px" }}
                      onClick={() => sendOtp()}
                    >
                      {Loading ? (
                        <CircularProgress color="inherit" size={20} />
                      ) : (
                        "Submit"
                      )}
                    </OutlinedBox>
                    <LoginText>
                      Don't have an account ?
                      <Span
                        onClick={() => {
                          setSignUpOpen(true);
                          dispatch(
                            closeSignin()
                          )
                        }}
                        style={{
                          fontWeight: "500",
                          marginLeft: "6px",
                          cursor: "pointer",
                        }}
                      >
                        Create Account
                      </Span>
                    </LoginText>
                  </>
                }
              </>

              :
              <OTP email={email} name="User" otpVerified={otpVerified} setOtpVerified={setOtpVerified} reason="FORGOTPASSWORD" />
            }

          </Wrapper>

        )}
      </Container>
    </Modal>
  );
};

export default SignIn;