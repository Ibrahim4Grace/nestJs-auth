export interface GoogleAuthPayload {
  id_token: string;
}
export interface CreateUserResponse {
  message: string;
  data: {
    user: {
      id: string;
      first_name: string;
      last_name: string;
      email: string;
      user_type: string;
    };
    token: string;
  };
}
