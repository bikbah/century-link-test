(function() {
  $(document).ready(function() {
    console.log("JS loaded..");

    $('#auth').click(function() {
      loginData = {
        login: "bah",
        password: "secret"
      }
      $.ajax({
        method: "POST",
        url: "http://localhost:8080/login",
        dataType: "json",
        data: JSON.stringify({"login": "bah", "password": "secret"}),
        contentType: "application/json",
        success: function(data){ console.log(data); }
      });
    });

    $('#secret').click(function() {
      $.ajax({
        method: "GET",
        url: "http://localhost:8080/secret",
        headers: {
          "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1Gd3dEUVlKS29aSWh2Y05BUUVCQlFBRFN3QXdTQUpCQUxiUnU5YXAxTmhsTHhxc0sremJuVUlqQXNRU010RllKdEZHTjVMclgrTCtvVWtsYjNUaUdUYS9rbWdGVE5IdVJCS052MERFbitpQ1duV1UyeXlhRkhjQ0F3RUFBUT09IiwidHlwIjoiSldUIn0.eyJleHAiOjE0MzQzNTc0OTd9.qYYg8a5OyiIC_oJq5q7zTco4h6npjnANg_jkUaH1i3I6dIoQgkN6mYE5V6ajBTGefskYUp6_bCxLdxUq3K_tag"
        }
      }).done(function(msg) {
        console.log(msg);
      });
    });

  });
})();
