# Phần 1 – Phân tích logic
Trong đoạn mã JwtAuthenticationFilter, có dòng:
if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt, null)) {
String username = tokenProvider.getUsernameFromJWT(jwt);
UserDetails userDetails = userDetailsService.loadUserByUsername(username);
}
# Vấn đề chính: validateToken(jwt, null) được gọi với tham số UserDetails = null.
Theo mẫu JwtTokenProvider trong tài liệu, phương thức validateToken thường có logic như sau:
public boolean validateToken(String token, UserDetails userDetails) {
String username = getUsernameFromJWT(token);
return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
}
Khi truyền null, đoạn kiểm tra userDetails.getUsername() sẽ gây lỗi hoặc luôn trả về false.

Kết quả: Token hợp lệ nhưng không bao giờ được xác nhận, dẫn đến việc không thiết lập Authentication trong SecurityContextHolder. Người dùng sẽ nhận lỗi 403 Forbidden.

# Điểm không nhất quán: JwtAuthenticationFilter gọi validateToken trước khi tải UserDetails, trong khi JwtTokenProvider lại cần UserDetails để xác thực.
# Điều này làm hỏng quy trình xác thực JWT.